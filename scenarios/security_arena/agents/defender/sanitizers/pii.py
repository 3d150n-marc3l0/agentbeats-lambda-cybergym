import re
from typing import List, Dict, Any

def sanitize_detected_tools(text: str, detected_tool_names: List[str]) -> str:
    """
    Elimina del texto UNICAMENTE las funciones que el auditor confirmó como filtradas.
    """
    if not detected_tool_names or not text:
        return text

    # Creamos el patrón solo con los culpables detectados
    pattern = re.compile(
        r'\b(' + '|'.join(map(re.escape, detected_tool_names)) + r')(?:\(\))?\b', 
        re.IGNORECASE
    )
    
    return pattern.sub("[RESTRICTED_ACCESS]", text)



def sanitize_detected_pii(text: str, detected_pii_list: list, governance_registry: dict) -> str:
    """
    detected_pii_list: Lista de tipos que el Auditor detectó (ej. ['EMAIL_ADDRESS'])
    governance_registry: Contiene el sub-diccionario 'protected_pii' con los regex.
    """
    pii_definitions = governance_registry.get("protected_pii", {})
    sanitized_text = text
    #print(pii_definitions)
    for pii_type in detected_pii_list:
        # 1. Buscamos la definición de esa entidad en nuestro registro
        entity_def = pii_definitions.get(pii_type)
        #print(f"t: {pii_type}, e: {entity_def}")
        if entity_def and "regex" in entity_def:
            pattern_str = entity_def["regex"]
            # 2. Aplicamos el Regex de forma dinámica
            pattern = re.compile(pattern_str, re.IGNORECASE)
            sanitized_text = pattern.sub(f"[{pii_type}_REDACTED]", sanitized_text)
            
    return sanitized_text
