from typing import Tuple, Dict, Any

from ..sanitizers.pii import sanitize_detected_pii, sanitize_detected_tools


def enforce_input_policies(llm_audit_json, governance_registry) -> Tuple[str, str]:
    # 1. Evaluar Ataques Directos (Prioridad 1)
    p_attack = llm_audit_json["direct_attack"]
    policy = governance_registry["direct_attacks"].get(p_attack["type"])
    if policy and p_attack["detected"]:
        if p_attack["confidence"] >= policy["thresholds"]["block"]:
            return "BLOCK", policy["messages"]["user_block"]
        
        if p_attack["confidence"] >= policy["thresholds"]["steer"]:
            steer_prompt = f"[SYSTEM_ADVISORY: {policy["messages"]['steer_instruction']}]"
            return "STEER", steer_prompt

    # 2. Evaluar Ataques Indirectos (Prioridad 2)
    i_attack = llm_audit_json["indirect_attack"]
    policy = governance_registry["indirect_attacks"].get(i_attack["type"])
    if policy and i_attack["detected"]:
        if i_attack["confidence"] >= policy["thresholds"]["block"]:
            return "BLOCK", policy["messages"]["user_block"]

    # 3. Evaluar Moderación (Prioridad 3 - "Stay Helpful")
    for filter_item in llm_audit_json["content_moderation"]["filters"]:
        policy_type = filter_item.get("type")
        action = filter_item.get("action")
        confidence = filter_item.get("confidence", 0)
        policy = governance_registry["content_moderation_policies"].get(policy_type)
        #print(f"policy_type: {policy_type}, policy: {policy}")
        
        if policy:
            # Si es muy evidente, bloqueamos el tema
            if action == "HIGH" and confidence >= policy["thresholds"]["block"]:
                return "BLOCK_TOPIC", policy["messages"]["user_block"]
            
            # Si es dudoso, activamos el "Warn Mode" para el Paso 2 (Asistente)
            if action == "MEDIUM" and confidence >= policy["thresholds"]["steer"]:
                #f"Attention: The user is asking about {policy_type}."
                return "WARN_ASSISTANT", policy["messages"]["assistant_steer"]
            
            if action == "LOW":
                # Opcional: Loguear para monitoreo de "Gray Areas"
                print(f"DEBUG: Content detected in gray area ({policy_type})")

    return "ALLOW", None



def enforce_output_policies(audit_output_json: Dict[str, Any], 
                            assistant_response: str, 
                            governance_registry: Dict[str, Any]) -> Tuple[str, str]:
    
    # 1.1 Identificar qué funciones detectó el Auditor con alta confianza
    instr_leak = audit_output_json.get("instruction_leak", {})
    tools_to_sanitize = []
    
    # 1.2. Ejecutar saneamiento QUIRÚRGICO
    for filter_item in instr_leak.get("filters", []):
        # SOLO si se detectó y supera el umbral de confianza
        if filter_item.get("detected") and filter_item.get("confidence", 0) > 0.85:
            # El 'type' en tu JSON contiene el nombre de la función detectada
            tools_to_sanitize.append(filter_item.get("type"))

    # 1.3. Ejecutar saneamiento QUIRÚRGICO
    # Solo actuamos sobre las funciones identificadas en 'tools_to_sanitize'
    if tools_to_sanitize:
        assistant_response = sanitize_detected_tools(assistant_response, tools_to_sanitize)

    # 2.1. Extraer detecciones de PII del JSON del Auditor
    pii_audit = audit_output_json.get("pii_leak", {})
    detected_pii_types = []
    
    # 2.2 Solo procesamos si el Auditor marcó 'detected': true
    for filter_item in pii_audit.get("filters", []):
        if filter_item.get("detected"):
            # Guardamos el tipo (ej: "EMAIL", "US_SOCIAL_SECURITY_NUMBER")
            detected_pii_types.append(filter_item.get("type"))

    # 2.3 Ejecutar la función de saneamiento con los tipos detectados
    # Pasamos el governance_registry que contiene los REGEX
    if detected_pii_types:
        print(f"detected_pii_types: {len(detected_pii_types)}")
        assistant_response = sanitize_detected_pii(
            assistant_response, 
            detected_pii_types, 
            governance_registry
        )

    # --- 3. MODERACIÓN DE CONTENIDO (Semántica) ---
    content_audit = audit_output_json.get("content_moderation", {})
    
    for filter_item in content_audit.get("filters", []):
        policy_type = filter_item.get("type")
        action = filter_item.get("action")
        confidence = filter_item.get("confidence", 0)
        policy = governance_registry["content_moderation_policies"].get(policy_type)
        #print(f"policy_type: {policy_type}, policy: {policy}")

        if policy:
            # Caso HIGH: Violación directa de política (ej: dar dosis médica o insultar)
            if action == "HIGH" and confidence >= policy["thresholds"]["block"]:
                return "BLOCK_TOPIC", policy["messages"]["user_block"]

            # Caso MEDIUM: Tono inadecuado o bordeando el límite
            if action == "MEDIUM" and confidence >= policy["thresholds"]["steer"]:
                # Aquí podrías devolver un mensaje que invite al usuario a reformular
                #return "REJECT_QUALITY_MEDIUM", "The generated response does not meet the domain's quality standards." + description
                steer_feedback = (
                    f"[SYSTEM_AUDIT_ADVISORY] Your previous response has been flagged with a MEDIUM risk "
                    f"rating in the safety category: '{policy_type}'.\n"
                    f"Contextual Constraint: {policy['description']}\n\n"
                    f"Instruction: Your draft violates the established safety and professional protocols "
                    f"defined for this specific task. Please refine and rewrite your response to be "
                    f"fully compliant. Maintain a helpful and accurate tone while strictly avoiding the "
                    f"flagged content or behavior mentioned above."
                )
                
                return "RETRY_WITH_STEER", steer_feedback

            # Caso LOW / SAFE: 
            # No hacemos nada, permitimos que el flujo continúe.
            if action == "LOW":
                # Opcional: Loguear para monitoreo de "Gray Areas"
                print(f"DEBUG: Content detected in gray area ({policy_type})")
        

    return "SUCCESS", assistant_response