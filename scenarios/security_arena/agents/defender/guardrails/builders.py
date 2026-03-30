from typing import Dict, Any

def build_guardrails_input(scenario_conf: Dict[str, Any], content_moderation: Dict[str, Any], prompt_attacks_registry:  Dict[str, Any]):
    guardrail_input_config = None

    if scenario_conf:
        default_contend_policies = "universal_safety_core"
        domain = scenario_conf["defender_role"]["identity"]["role_class"]
        content_moderation_policies = content_moderation.get("domains", {}).get(domain, {}).get("domain_policies", {})
        if not content_moderation_policies:
            content_moderation_policies = content_moderation.get(default_contend_policies, {})

        direct_attacks = prompt_attacks_registry.get("direct_attacks", [])
        indirect_attacks = prompt_attacks_registry.get("indirect_attacks", [])
        
        guardrail_input_config = {
            "direct_attacks": direct_attacks,
            "indirect_attacks": indirect_attacks,
            "content_moderation_policies": content_moderation_policies,
            "domain_name": domain
        }
    return guardrail_input_config


def build_guardrails_output(scenario_conf: Dict[str, Any], content_moderation: Dict[str, Any], pii_attacks_registry: Dict[str, Any]):
    guardrail_output_config = None
    if scenario_conf:
        default_contend_policies = "universal_safety_core"
        defender_role = scenario_conf["defender_role"]
        defender_task = scenario_conf["defender_task"]
        domain = defender_role["identity"]["role_class"]
        content_moderation_policies = content_moderation.get("domains", {}).get(domain, {}).get("domain_policies", {})
        if not content_moderation_policies:
            content_moderation_policies = content_moderation.get(default_contend_policies, {})
        
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
                    default_pii = pii_attacks_registry["PII_ENTITIES"]["UNCATEGORIZED_SENSITIVE_DATA"]
                    if pii_cat not in protected_pii:
                        protected_pii[pii_cat] = pii_attacks_registry["PII_ENTITIES"].get(pii_cat, default_pii)
                        protected_pii[pii_cat]["keys"] = []
                    protected_pii[pii_cat]["keys"].append(pii_key)
        
        guardrail_output_config = {
            "content_moderation_policies": content_moderation_policies,
            "protected_tools": protected_tools,
            "protected_pii": protected_pii,
            "domain_name": domain
        }
    return guardrail_output_config