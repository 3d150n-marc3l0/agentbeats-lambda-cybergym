#!/usr/bin/env python3
"""
Defender Agent - Processes inputs and performs assigned tasks.

Receives filtered scenario context as JSON (no attack info), builds dynamic prompts,
and processes formatted input according to the scenario.
"""

import argparse
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any
import uvicorn
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader
from dataclasses import replace
load_dotenv()

from openai import AsyncOpenAI

# Load templates
_template_dir = Path(__file__).parent / "templates"
_env = Environment(loader=FileSystemLoader(_template_dir), trim_blocks=True, lstrip_blocks=True)
_system_template = _env.get_template("system.j2")
_user_template = _env.get_template("user.j2")

# Guardrails: Input and Ouput
_system_guardrail_input_template = _env.get_template("system_guardrail_input.j2")
_user_guardrail_input_template = _env.get_template("user_guardrail_input.j2")
_system_guardrail_output_template = _env.get_template("system_guardrail_output.j2")
_user_guardrail_output_template = _env.get_template("user_guardrail_output.j2")

# Files moderation:
def read_json(file_path: str):
    with open(file_path, "r") as f:
        json_data = json.load(f)
    return json_data
_prompt_attacks_registry_path = _template_dir / "attacks_registry.json"
_pii_attacks_registry_path = _template_dir / "pii_attacks.json"
_content_moderation_path = _template_dir / "content_moderation.json"
_prompt_attacks_registry = read_json(_prompt_attacks_registry_path)
_pii_attacks_registry = read_json(_pii_attacks_registry_path)
_content_moderation = read_json(_content_moderation_path)



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
logger = logging.getLogger("defender")

from .parsers.parser_scenario import parser_defender_scenario
from .sanitizers.proccessor import preprocess_input
from .guardrails.shield import enforce_input_policies, enforce_output_policies
from .guardrails.extraction import extract_json


@dataclass
class ScenarioContext:
    """Filtered scenario context from orchestrator (no attack info)."""
    domain_description: str   # Domain/system description
    defender_role: str        # Defender's role description
    defender_task: str        # What defender should do
    output_format: str        # Expected output format
    formatted_input: str      # Input to process

    @classmethod
    def from_dict(cls, d: dict) -> "ScenarioContext":
        return cls(
            domain_description=d.get("domain_description", ""),
            defender_role=d.get("defender_role", ""),
            defender_task=d.get("defender_task", ""),
            output_format=d.get("output_format", ""),
            formatted_input=d.get("formatted_input", ""),
        )


class Defender(AgentExecutor):
    """Defender that processes inputs according to scenario context."""

    def __init__(self, model: str = "gpt-4o-mini"):
        self.client = AsyncOpenAI(
            api_key=os.getenv("OPENAI_API_KEY"),
            base_url=os.getenv("OPENAI_BASE_URL")
        )
        self.model = model

    def _render(self, template, ctx: ScenarioContext) -> str:
        """Render a Jinja2 template with the scenario context."""
        return template.render(**vars(ctx))
    
    def _build_guardrails_input(self, scenario_conf: Dict[str, Any]):
        guardrail_input_config = None

        if scenario_conf:
            default_contend_policies = "universal_safety_core"
            domain = scenario_conf["defender_role"]["identity"]["role_class"]
            content_moderation_policies = _content_moderation.get("domains", {}).get(domain, {}).get("domain_policies", {})
            if not content_moderation_policies:
                content_moderation_policies = _content_moderation.get(default_contend_policies, {})

            direct_attacks = _prompt_attacks_registry.get("direct_attacks", [])
            indirect_attacks = _prompt_attacks_registry.get("indirect_attacks", [])
            
            guardrail_input_config = {
                "direct_attacks": direct_attacks,
                "indirect_attacks": indirect_attacks,
                "content_moderation_policies": content_moderation_policies,
                "domain_name": domain
            }
        return guardrail_input_config

    
    def _build_guardrails_output(self, scenario_conf: Dict[str, Any]):
        guardrail_output_config = None
        if scenario_conf:
            default_contend_policies = "universal_safety_core"
            defender_role = scenario_conf["defender_role"]
            defender_task = scenario_conf["defender_task"]
            domain = defender_role["identity"]["role_class"]
            content_moderation_policies = _content_moderation.get("domains", {}).get(domain, {}).get("domain_policies", {})
            if not content_moderation_policies:
                content_moderation_policies = _content_moderation.get(default_contend_policies, {})
            
            # Internal tools
            constraints = defender_role["constraints"] + defender_task["constraints"]
            #print(f"LEN: {len( defender_role["constraints"])}")
            #print(f"LEN: {defender_task["constraints"]}")
            #print(f"LEN: {len(constraints)}")
            protected_tools = {}
            protected_pii = {}
            for constraint in constraints:
                sent = constraint["sentence"]
                const_class = constraint["constraint_class"]
                actions = constraint.get("actions", [])
                #print(f"const_class: {const_class}, SENT: {sent}")
                # Tools
                if const_class == "STRICT_PROHIBITION":
                    for action in actions:
                        tool_nane = action["name"]
                        #print(action["type"] )
                        if action["type"] == "TOOL":
                            protected_tools[tool_nane] = action
                
                # PII
                if const_class == "DATA_SENSITIVITY":
                    curr_pii_entities = []
                    curr_pii_entities += constraint.get("pii", []) 
                    for action in actions:
                        if action["type"] == "INTERNAL_RECORD":
                            curr_pii_entities += action.get("pii", []) 
                    # Map 
                    for pii in curr_pii_entities:
                        pii_cat = pii["category"]
                        pii_key = pii["key"]
                        default_pii = _pii_attacks_registry["PII_ENTITIES"]["UNCATEGORIZED_SENSITIVE_DATA"]
                        if pii_cat not in protected_pii:
                            protected_pii[pii_cat] = _pii_attacks_registry["PII_ENTITIES"].get(pii_cat, default_pii)
                            protected_pii[pii_cat]["keys"] = []
                        protected_pii[pii_cat]["keys"].append(pii_key)
            
            guardrail_output_config = {
                "content_moderation_policies": content_moderation_policies,
                "protected_tools": protected_tools,
                "protected_pii": protected_pii,
                "domain_name": domain
            }
        return guardrail_output_config

    async def _generate(self, system: str, user: str) -> str:
        """Generate a response from the LLM."""
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}]
        )
        content = response.choices[0].message.content
        return content if content is not None else ""

    async def execute(self, context: RequestContext, event_queue: EventQueue):
        """Process input based on scenario context."""
        if not context.message:
            raise ServerError(error=InvalidParamsError(message="Missing message."))

        task = new_task(context.message)
        await event_queue.enqueue_event(task)
        updater = TaskUpdater(event_queue, task.id, task.context_id)

        try:
            # Parse JSON context from orchestrator into dataclass
            message_text = context.get_user_input()
            ctx = ScenarioContext.from_dict(json.loads(message_text))
            logger.info("Processing: role=%s...", ctx.defender_role[:50])
            logger.info(f"[Processing] QUESTION: {ctx.formatted_input}")

            # 1. Parsing description role and description task
            scenario_conf = parser_defender_scenario(ctx.defender_role, ctx.defender_task)

            # 2. Sanitizacion
            sanitized_text = preprocess_input(ctx.formatted_input)
            logger.info(f"[Processing] SANITIZED: {sanitized_text}")

            # 3 Guardrail Input
            action, message = "ALLOW", None
            guardrail_input_config = self._build_guardrails_input(scenario_conf)
            if guardrail_input_config:
                # 2.1 Add Sanitized Input
                guardrail_input_config["user_input"] = sanitized_text

                # 2.1 Run Guardrail Input
                guardrail_input = await self._generate(
                    _system_guardrail_input_template.render(**guardrail_input_config),
                    _user_guardrail_input_template.render(**guardrail_input_config)
                )
                logger.info(f"[GUARDRAIL-INPUT] result: {guardrail_input}")
                guardrail_input = extract_json(guardrail_input)

                # 2.2 Enforce security
                action, message = enforce_input_policies(guardrail_input, guardrail_input_config)
                logger.info(f"[ENFORCE-INPUT-POLICIES] ACTION: {action}, ANSWER: {message}")
            
            if action == "BLOCK":
                logger.info("[BLOCK] Generated response (%d chars)", len(message))
                await updater.update_status(TaskState.completed, new_agent_text_message(message))
            else:
                # Render Jinja2 templates with context and generate response
                new_ctx = replace(
                    ctx,
                    output_format=sanitized_text
                )
                assistant_output = await self._generate(
                    self._render(_system_template, new_ctx),
                    self._render(_user_template, new_ctx)
                )
                logger.info("[ASSISTENT] Generated response (%d chars)", len(assistant_output))

                # Guardrail Output
                action, response_output = "SUCCESS", assistant_output
                guardrail_output_config = self._build_guardrails_output(scenario_conf)
                if guardrail_output_config and assistant_output:
                    # Add Assistant Output
                    guardrail_output_config["assistant_output"] = response_output

                    # 2.1 Run Guardrail Input
                    guardrail_output = await self._generate(
                        _system_guardrail_output_template.render(**guardrail_output_config),
                        _user_guardrail_output_template.render(**guardrail_output_config)
                    )
                    logger.info(f"[GUARDRAIL-OUTPUT] result: {guardrail_output}")
                    guardrail_output = extract_json(guardrail_output)

                    # 2.2 Enforce security
                    action, response_output = enforce_output_policies(
                        audit_output_json=guardrail_output, 
                        assistant_response=assistant_output, 
                        governance_registry=guardrail_output_config
                    )
                    logger.info(f"[ENFORCE-OUTPUT-POLICIES] ACTION: {action}, ANSWER: {response_output}")

                logger.info(f"[FINAL-RESPONSE] ANSWER: {response_output}")
                await updater.update_status(TaskState.completed, new_agent_text_message(response_output))
        except Exception as e:
            logger.error("Defender error: %s", e, exc_info=True)
            await updater.update_status(TaskState.failed, new_agent_text_message(f"Error: {e}"))

    async def cancel(self, _request: RequestContext, _event_queue: EventQueue) -> Task | None:
        raise ServerError(error=UnsupportedOperationError())


def main():
    parser = argparse.ArgumentParser(description="Security Arena - Defender Agent")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=9020, help="Port to bind to")
    parser.add_argument("--model", default="gpt-4o-mini", help="OpenAI model to use")
    args = parser.parse_args()

    agent_card = AgentCard(
        name="defender",
        description="Defender agent that processes inputs according to role",
        url=f"http://{args.host}:{args.port}/",
        version="1.0.0",
        default_input_modes=["text"],
        default_output_modes=["text"],
        capabilities=AgentCapabilities(streaming=False),
        skills=[]
    )

    executor = Defender(model=args.model)
    task_store = InMemoryTaskStore()
    request_handler = DefaultRequestHandler(agent_executor=executor, task_store=task_store)
    app = A2AStarletteApplication(agent_card=agent_card, http_handler=request_handler)

    print(f"Starting Defender on http://{args.host}:{args.port} (model: {args.model})")
    uvicorn.run(app.build(), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
