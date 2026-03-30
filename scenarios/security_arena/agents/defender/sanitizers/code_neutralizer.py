import re

def neutralize_code_blocks(text: str) -> str:
    """
    Envuelve o modifica bloques de código para que el LLM los trate como 
    datos pasivos, no como instrucciones.
    """
    # 1. Neutralizar triple backticks para que no rompan tu Markdown/Prompt
    # Cambiamos ``` por [CODE_BLOCK]
    text = text.replace("```", "\n[LITERAL_CODE_SECTION]\n")

    # 2. Detectar patrones de ejecución peligrosos y comentarlos
    # Si detectamos exec(), eval() o import os, les añadimos un prefijo de advertencia
    dangerous_patterns = [
        (r'exec\s*\(', 'REDACTED_EXEC('),
        (r'eval\s*\(', 'REDACTED_EVAL('),
        (r'import\s+os', '# BLOCKED_IMPORT_OS'),
        (r'import\s+subprocess', '# BLOCKED_IMPORT_SUBPROCESS')
    ]
    
    for pattern, replacement in dangerous_patterns:
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)

    return text


def neutralize_template_injection(text: str) -> str:
    """
    Neutraliza sintaxis de template engines (Jinja2, Handlebars, etc.)
    sin eliminar contenido semántico.
    """

    # {{ variable }} o {{ expression }}
    text = re.sub(r'{{', '[TEMPLATE_OPEN]', text)
    text = re.sub(r'}}', '[TEMPLATE_CLOSE]', text)

    # ${expression} (JS, bash-like)
    text = re.sub(r'\$\{.*?\}', '[TEMPLATE_EXPR]', text)

    # {% control structures %}
    text = re.sub(r'{%\s*.*?\s*%}', '[TEMPLATE_BLOCK]', text)

    return text