#!/usr/bin/env python3
"""
Attacker Agent - Red team agent for security testing.

Receives scenario context as JSON, builds strategic prompts, and generates attacks.
Works across different scenarios by adapting to context dynamically.
"""

import argparse
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
import heapq
import random
import uvicorn
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader

load_dotenv()

from openai import AsyncOpenAI

# Load templates
_template_dir = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(_template_dir), trim_blocks=True, lstrip_blocks=True)
_system_template = _env.get_template("system.j2")
_user_template = _env.get_template("user.j2")
# Ranking templates
_system_ranking_template = _env.get_template("system_ranking.j2")
_user_ranking_template = _env.get_template("user_ranking.j2")
# Mutate templates
_system_mutate_template = _env.get_template("system_mutate.j2")
_user_mutate_template = _env.get_template("user_mutate.j2")

# Files moderation:
def read_json(file_path: str):
    with open(file_path, "r") as f:
        json_data = json.load(f)
    return json_data
_prompt_attacks_registry_path = _template_dir / "attacks_registry.json"
_pii_attacks_registry_path = _template_dir / "pii_attacks.json"
_prompt_attacks_registry = read_json(_prompt_attacks_registry_path)
_pii_attacks_registry = read_json(_pii_attacks_registry_path)



from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore, TaskUpdater
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import (
    AgentCard, AgentCapabilities, TaskState,
    InvalidParamsError, UnsupportedOperationError, Task
)
from a2a.utils import new_agent_text_message, new_task
from a2a.utils.errors import ServerError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("attacker")



from ..defender.parsers.parser_scenario import parser_defender_scenario
from ..defender.guardrails.extraction import extract_json
from .utils import build_defender_scenario, analyze_defender_response
from .strategy import select_top_k_attack_strategies



@dataclass
class ScenarioContext:
    """Scenario context from orchestrator for attack generation."""
    attack_type: str                        # INJECTION (embedded) or DIRECT (message)
    domain_description: str                 # Domain/system being attacked
    attack_goal: str                        # What attacker is trying to achieve
    attack_constraints: list[str]           # Rules attacker must follow
    max_number_of_rounds: int               # Maximum battle rounds
    defender_role: str                      # Defender's role description
    defender_task: str                      # What defender does
    output_format: str                      # Expected defender output format
    input_format_template: str              # Template with PLACE_ATTACK_HERE
    current_round: int = 0                  # Current round (0-indexed)
    battle_history: list[dict] = field(default_factory=list)  # Previous rounds

    @classmethod
    def from_dict(cls, d: dict) -> "ScenarioContext":
        return cls(
            attack_type=d.get("attack_type", "DIRECT"),
            domain_description=d.get("domain_description", ""),
            attack_goal=d.get("attack_goal", ""),
            attack_constraints=d.get("attack_constraints", []),
            max_number_of_rounds=d.get("max_number_of_rounds", 5),
            defender_role=d.get("defender_role", ""),
            defender_task=d.get("defender_task", ""),
            output_format=d.get("output_format", ""),
            input_format_template=d.get("input_format_template", ""),
            current_round=d.get("current_round", 0),
            battle_history=d.get("battle_history", []),
        )


class Attacker(AgentExecutor):
    """Red team attacker that generates strategic attacks based on scenario context."""

    def __init__(self, model: str = "gpt-4o-mini"):
        self.client = AsyncOpenAI(
            api_key=os.getenv("OPENAI_API_KEY"),
            base_url=os.getenv("OPENAI_BASE_URL")
        )
        self.model = model

        # Example: Store custom data across rounds. Participants can extend this
        # to track strategy, patterns, or any data useful for future attacks.
        # Keyed by round number (0-indexed). Agent restarts with each battle.
        self.round_data: dict[int, dict] = {}
        self.strategy_ranking: dict[str, dict] = {}
        
        for category, strategy in _prompt_attacks_registry.items():
            attacks = []
            for attack_type, attack in strategy.items():
                attack["type"] = attack_type
                attacks.append(attack)
            random.shuffle(attacks)
            self.strategy_ranking[category] = {
                "attacks": attacks,
                "current_index": 0
            }
        #logger.info(f"Strategy ranking: {self.strategy_ranking}")

    def _render(self, template, ctx: ScenarioContext, **extra) -> str:
        """Render a Jinja2 template with the scenario context and extra data."""
        return template.render(**vars(ctx), **extra)

    async def _generate(self, system: str, user: str) -> str:
        """Generate a response from the LLM."""
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}]
        )
        content = response.choices[0].message.content
        return content if content is not None else ""

    async def execute(self, context: RequestContext, event_queue: EventQueue):
        """Generate an attack based on scenario context."""
        if not context.message:
            raise ServerError(error=InvalidParamsError(message="Missing message."))

        task = new_task(context.message)
        await event_queue.enqueue_event(task)
        updater = TaskUpdater(event_queue, task.id, task.context_id)

        try:
            # Parse JSON context from orchestrator into dataclass
            message_text = context.get_user_input()
            ctx = ScenarioContext.from_dict(json.loads(message_text))
            logger.info("Round %d: Type=%s, History=%d",
                        ctx.current_round + 1, ctx.attack_type, len(ctx.battle_history))


            if ctx.battle_history and len(ctx.battle_history) > 0:
                # We don't have defender_scenario here yet if it's round 0 and we just got history
                # but usually round 0 has no history. If it does, we need to handle it.
                pass
            
            # 1. Inicialización de Memoria (Ronda 0)
            ranking_output = None
            attack_output = None
            defender_response = None
            next_strategy = None
            last_strategy = None
            attack_analysis = {}
            logger.info("Round %d: Type=%s, History=%d",
                        ctx.current_round + 1, ctx.attack_type, len(ctx.battle_history))
            if ctx.current_round == 0:
                # 1. Parsing description role and description task
                scenario_conf = parser_defender_scenario(
                    ctx.defender_role, 
                    ctx.defender_task,
                    ctx.output_format
                )
                defender_scenario = build_defender_scenario(scenario_conf, _pii_attacks_registry)

                # Seleccionamos la siguiente estrategia
                #next_strategy = select_next_attack_strategy(self.strategy_ranking, ctx.attack_type)
                attacks = self.strategy_ranking[ctx.attack_type]["attacks"]
                current_index = self.strategy_ranking[ctx.attack_type]["current_index"]
                new_strategy = attacks[current_index]
                self.strategy_ranking[ctx.attack_type]["current_index"] += 1
            else: 
                # 1. Obtener el escenario del defensor
                round_data = self.round_data[ctx.current_round - 1]
                logger.info(f"[ROUND-DATA] round_data: {round_data.keys()}")
                defender_scenario = round_data["defender_scenario"]
                old_strategy = round_data["strategy_used"]
                last_strategy = round_data["next_strategy"]
                attack_output = round_data["attack_output"]

                # 2. Obtener la respuesta del defensor
                last_battle = ctx.battle_history[-1]
                defender_response = last_battle["defender_response"]
                logger.info("[BATTLE-INFO] Defender response: %s", defender_response)
                
                # 3. Analizar la respuesta del defensor
                attack_analysis = analyze_defender_response(defender_response, defender_scenario)

                # Ranking last attack
                # Render Jinja2 templates with context and stored data, then generate attack
                ranking_context = {
                    "attack": last_strategy,
                    "defender_scenario": defender_scenario,
                    "attack_analysis": attack_analysis,
                    "defender_response": defender_response
                }
                system_prompt_ranking = self._render(_system_ranking_template, ctx, **ranking_context)
                logger.info(f"[RANKING-OUTPUT] system_prompt_ranking: {system_prompt_ranking}")
                user_prompt_ranking = self._render(_user_ranking_template, ctx, **ranking_context)
                logger.info(f"[RANKING-OUTPUT] user_prompt_ranking: {user_prompt_ranking}")
                ranking_output = await self._generate(
                    system_prompt_ranking,
                    user_prompt_ranking
                )
                logger.info(f"[RANKING-OUTPUT] result: {ranking_output}")
                ranking_output = extract_json(ranking_output)
            
                if ranking_output["level"] == "REJECTED":
                    # Seleccionamos la siguiente estrategia
                    attacks = self.strategy_ranking[ctx.attack_type]["attacks"]
                    current_index = self.strategy_ranking[ctx.attack_type]["current_index"] % len(attacks)
                    new_strategy = attacks[current_index]
                    self.strategy_ranking[ctx.attack_type]["current_index"] += 1
                elif ranking_output["level"] == "PARTIAL_LEAK" or ranking_output["level"] == "TASK_HIJACK":
                    # Mutamos la estrategia
                    mutation_context = {
                        "last_strategy": last_strategy,
                        "attack_output": attack_output,
                        "defender_response": defender_response,
                        "attack_analysis": attack_analysis
                    }
                    system_prompt_mutation = self._render(_system_mutate_template, ctx, **mutation_context)
                    logger.info(f"[MUTATION-OUTPUT] system_prompt_mutation: {system_prompt_mutation}")
                    user_prompt_mutation = self._render(_user_mutate_template, ctx, **mutation_context)
                    logger.info(f"[MUTATION-OUTPUT] user_prompt_mutation: {user_prompt_mutation}")
                    new_strategy_description = await self._generate(
                        system_prompt_mutation,
                        user_prompt_mutation
                    )
                    logger.info(f"[MUTATION-OUTPUT] new_strategy_description: {new_strategy_description}")

                    new_strategy = {
                        "description": new_strategy_description,
                        "type": strategy_used["type"],
                        "mustated": True,
                        "parent": strategy_used
                    }
            

            # Example: Retrieve previously stored data for this battle.
            # This is separate from battle_history - use it to store custom data
            # like strategy notes, patterns observed, or any analysis results.
            # Keyed by round number. Agent restarts with each battle, so no need for context_id.
            
            #stored_rounds = dict(self.round_data)  # Copy for template
            # 4. Seleccionar las top k estrategias
            logger.info(f"[GENERATED-ATTACK] len(self.round_data): {len(self.round_data)}")
            #logger.info(f"[GENERATED-ATTACK] self.round_data: {self.round_data}")
            def sort_rounds(x: tuple) -> tuple:
                ranking = x[1].get("attack_ranking") or {}
                confidence = ranking.get("confidence") or 0
                return float(confidence), x[0]

            stored_rounds = heapq.nlargest(
                2, 
                self.round_data.items(), 
                key=sort_rounds
            )
            stored_rounds = [item for item in stored_rounds if item[1].get("attack_ranking", {})]

            # Render Jinja2 templates with context and stored data, then generate attack
            system_prompt_attack = self._render(_system_template, ctx, next_strategy=new_strategy)
            logger.info(f"[ATTACK-OUTPUT] system_prompt_attack: {system_prompt_attack}")
            user_prompt_attack = self._render(_user_template, ctx, stored_rounds=stored_rounds)
            logger.info(f"[ATTACK-OUTPUT] user_prompt_attack: {user_prompt_attack}")
            attack_output = await self._generate(
                system_prompt_attack,
                user_prompt_attack
            )
            logger.info("[GENERATED-ATTACK] Generated attack (%d chars)", len(attack_output))
            logger.info(f"[GENERATED-ATTACK] attack_output: {attack_output}")

            # Example: Store data for future rounds. Here we just store word_count,
            # but participants can extend this to store anything useful.
            self.round_data[ctx.current_round] = {
                "defender_response": defender_response,
                "strategy_used": last_strategy,
                "defender_mentioned_tools": attack_analysis.get("protected_tools", []),
                "defender_mentioned_pii_entities": attack_analysis.get("protected_pii", []),
                "defender_refused": attack_analysis.get("detected_rejected_response", {}).get("rejected", False),
                "defender_refused_confidence": attack_analysis.get("detected_rejected_response", {}).get("confidence", 0),
                "attack_ranking": ranking_output,
                "next_strategy": new_strategy,
                "attack_output": attack_output,
                "defender_scenario": defender_scenario
            }
            logger.info(f"[ROUND-DATA] round: {ctx.current_round} - round_data: {len(self.round_data)}")

            
            await updater.update_status(TaskState.completed, new_agent_text_message(attack_output))
        except Exception as e:
            self.round_data[ctx.current_round] = {}
            logger.error("[ATTACKER-ERROR] Attacker error: %s", e, exc_info=True)
            await updater.update_status(TaskState.failed, new_agent_text_message(f"Error: {e}"))

    async def cancel(self, _request: RequestContext, _event_queue: EventQueue) -> Task | None:
        raise ServerError(error=UnsupportedOperationError())


def main():
    parser = argparse.ArgumentParser(description="Security Arena - Attacker Agent")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=9021, help="Port to bind to")
    parser.add_argument("--model", default="gpt-4o-mini", help="OpenAI model to use")
    args = parser.parse_args()

    agent_card = AgentCard(
        name="attacker",
        description="Red team attacker for security testing",
        url=f"http://{args.host}:{args.port}/",
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=False),
        skills=[]
    )

    executor = Attacker(model=args.model)
    task_store = InMemoryTaskStore()
    request_handler = DefaultRequestHandler(agent_executor=executor, task_store=task_store)
    app = A2AStarletteApplication(agent_card=agent_card, http_handler=request_handler)

    print(f"Starting Attacker on http://{args.host}:{args.port} (model: {args.model})")
    uvicorn.run(app.build(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
