import re

def strip_structural_attack_markers2(text: str) -> str:
    """
    Elimina marcadores que intentan suplantar al sistema o romper la estructura.
    """
    # 1. Neutralizar Comentarios HTML (muy usados para inyección indirecta)
    # Ejemplo: text = text.replace("", "[BLOCK_END]")
    
    # 2. Neutralizar Suplantación de Roles (Case Insensitive)
    # Buscamos patrones como [SYSTEM], [ADMIN], [INSTRUCTION], (SYSTEM), etc.
    roles_to_neutralize = [
        r'\[\s*SYSTEM\s*\]', r'\[\s*ADMIN\s*\]', r'\[\s*USER\s*\]',
        r'\[\s*INSTRUCTION\s*\]', r'\[\s*COMMAND\s*\]', r'\[\s*ROOT\s*\]',
        r'<\s*SYSTEM\s*>', r'<\s*ADMIN\s*>'
    ]
    for role_pattern in roles_to_neutralize:
        text = re.sub(role_pattern, "[USER_TEXT_REDACTED]", text, flags=re.IGNORECASE)

    # 3. Proteger tus propios Delimitadores Semánticos
    # Si el atacante escribe [PRIMARY_TASK] en su input, lo invalidamos 
    # para que el LLM no se confunda con tu etiqueta real.
    internal_labels = [
        "[IDENTITY_AND_MANDATE]", "[DOMAIN_CONTEXT]", "[ASSIGNED_ROLE]", 
        "[PRIMARY_TASK]", "[MANDATORY_JSON_SCHEMA]", "[SECURITY_PROTOCOLS]",
        "[ANTI_JAILBREAK_PROTOCOLS]", "[PRIVACY_PROTOCOLS]"
    ]
    for label in internal_labels:
        # Usamos un reemplazo que mantenga el texto pero rompa la etiqueta
        text = text.replace(label, f"INVALID_TAG_{label}")

    # 4. Evitar el cierre de tu "cárcel" XML
    # Si usas <untrusted_input> en tu prompt, neutralizamos cualquier intento de cerrarlo.
    text = re.sub(r'</?\s*untrusted_input\s*>', '[TAG_INVALIDATED]', text, flags=re.IGNORECASE)

    return text



def strip_structural_attack_markers(text: str) -> str:
    """
    Elimina marcadores que intentan suplantar al sistema o romper la estructura.
    """

    # 1. Neutralizar Suplantación de Roles (incluye cierre XML)
    roles_pattern = [
        r'\[\s*SYSTEM\s*\]', r'\[\s*ADMIN\s*\]', r'\[\s*USER\s*\]',
        r'\[\s*INSTRUCTION\s*\]', r'\[\s*COMMAND\s*\]', r'\[\s*ROOT\s*\]',
        r'<\s*/?\s*SYSTEM\s*>', r'<\s*/?\s*ADMIN\s*>'
    ]
    for pattern in roles_pattern:
        text = re.sub(pattern, "[USER_TEXT_REDACTED]", text, flags=re.IGNORECASE)

    # 2. Neutralizar roles tipo conversación (muy importante)
    text = re.sub(
        r'\b(System|Assistant|User)\s*:',
        '[ROLE_REDACTED]:',
        text,
        flags=re.IGNORECASE
    )

    # 3. Proteger delimitadores internos
    #internal_labels = [
    #    "[IDENTITY_AND_MANDATE]", "[DOMAIN_CONTEXT]", "[ASSIGNED_ROLE]", 
    #    "[PRIMARY_TASK]", "[MANDATORY_JSON_SCHEMA]", "[SECURITY_PROTOCOLS]",
    #    "[ANTI_JAILBREAK_PROTOCOLS]", "[PRIVACY_PROTOCOLS]"
    #]
    #for label in internal_labels:
    #    text = text.replace(label, f"INVALID_TAG_{label}")
    
    internal_labels = [
        "IDENTITY_AND_MANDATE", "DOMAIN_CONTEXT", "ASSIGNED_ROLE", 
        "PRIMARY_TASK", "MANDATORY_JSON_SCHEMA", "SECURITY_PROTOCOLS",
        "ANTI_JAILBREAK_PROTOCOLS", "PRIVACY_PROTOCOLS"
    ]

    for label in internal_labels:
        pattern = rf'\[\s*{label}\s*\]'
        replacement = f"[INVALID_TAG_{label}]"
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)

    # 4. Evitar cierre de tu XML interno
    text = re.sub(
        r'</?\s*untrusted_input\s*>',
        '[TAG_INVALIDATED]',
        text,
        flags=re.IGNORECASE
    )

    # 5. Neutralizar template injection (Jinja, handlebars, etc.)
    #text = re.sub(r'{{|}}', '[TEMPLATE_TOKEN]', text)
    #text = re.sub(r'\$\{.*?\}', '[TEMPLATE_EXPR]', text)

    # 6. Neutralizar bloques de código markdown
    #text = text.replace("```", "[CODE_BLOCK]")

    return text

def remove_html_comments(text: str) -> str:
    """
    Elimina todos los comentarios HTML o XML del texto.
    Maneja comentarios multilínea y evita romper el contenido circundante.

    Ejemplos de comentarios que elimina:
      <!-- Esto es un comentario -->
      <!-- Comentario
           multilínea -->
    """
    # Eliminamos todos los <!-- ... --> usando DOTALL para incluir saltos de línea
    text = re.sub(r'<!--.*?-->', '', text, flags=re.DOTALL)
    
    # 2. Eliminar comentarios no cerrados <!-- ... (hasta EOF)
    text = re.sub(r'<!--.*$', '', text, flags=re.DOTALL)

    # 3. Eliminar residuos típicos de evasión (-->, --!>, etc.)
    text = re.sub(r'--\s*!?>', '', text)
    
    return text


def remove_html_comments2(text: str) -> str:
    """
    Elimina comentarios HTML/XML dejando una marca de seguridad neutra.
    """
    # 1. Usamos una marca para que el LLM sepa que ahí había metadatos no confiables
    # Sustituimos por un marcador que no rompa la semántica
    cleaned_text = re.sub(r'', ' [COMMENT_REDACTED] ', text, flags=re.DOTALL)
    
    # 2. En lugar de colapsar TODO el texto a una sola línea con .strip(), 
    # mejor solo limpiamos los espacios dobles creados por nuestra marca.
    cleaned_text = re.sub(r' +', ' ', cleaned_text) 
    
    return cleaned_text.strip()


