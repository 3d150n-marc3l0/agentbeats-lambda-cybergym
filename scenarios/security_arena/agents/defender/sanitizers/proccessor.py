from .code_neutralizer import neutralize_code_blocks, neutralize_template_injection
from .encoding import decode_and_normalize_payloads
from .markers import remove_html_comments, strip_structural_attack_markers
from .normalization import normalize_unicode, normalize_whitespace, remove_control_chars

def preprocess_input(raw_text: str) -> str:
    """
    Orquestador de la Capa 0: Desinfección Pasiva.
    """
    # 1. Limpieza de superficie y Unicode
    text = normalize_unicode(raw_text)
    text = remove_control_chars(text)

    # 2. Eliminación de comentarios (Antes de decodificar)
    text = remove_html_comments(text)
    
    # 3. Decodificación de Payloads (B64/Hex) -> [REDACTED_B64]
    text = decode_and_normalize_payloads(text)
    
    # 4. NEUTRALIZACIÓN DE CÓDIGO (NUEVA)
    # Desarmamos la lógica de programación para que el LLM no la "ejecute" mentalmente
    text = neutralize_template_injection(text)
    text = neutralize_code_blocks(text)
    
    # 5. Neutralización de Roles/Marcadores
    text = strip_structural_attack_markers(text)
    
    # 6. Normalización final de espacios
    #text = normalize_whitespace(text)
    
    return text