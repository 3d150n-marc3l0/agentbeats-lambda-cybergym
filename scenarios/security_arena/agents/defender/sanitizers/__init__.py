# sanitizers/__init__.py
from .normalization import normalize_unicode, remove_control_chars, normalize_whitespace
from .encoding import decode_and_normalize_payloads
from .markers import strip_structural_attack_markers
from .code_neutralizer import neutralize_code_blocks

def sanitize_user_input(raw_input: str, max_length: int = 4000) -> str:
    """
    Orquesta todos los sanitizadores en el orden lógico de seguridad.
    """
    # 1. DEFENSA PASIVA (Limpieza de superficie)
    # Primero quitamos lo que "ensucia" el texto sin cambiar su significado
    text = normalize_unicode(raw_input)
    text = remove_control_chars(text)
    
    # 2. CONTROL DE VOLUMEN (Anti-Flood)
    # Cortamos el input si es demasiado largo para evitar ataques de denegación de servicio (DoS)
    # o "Prompt Stuffing" que llene la ventana de contexto.
    text = text[:max_length]
    
    # 3. REVELACIÓN (Decoding)
    # Ahora que el texto es "limpio", buscamos ataques ocultos en Base64 o Hex.
    # Es vital hacerlo ANTES de limpiar markers, por si el ataque estaba encodeado.
    text = decode_and_normalize_payloads(text)
    
    # 4. NEUTRALIZACIÓN ESTRUCTURAL
    # Ahora que el ataque es visible (si lo había), rompemos las etiquetas de 
    # suplantación de sistema [SYSTEM] y los cierres de etiquetas </untrusted_input>.
    text = strip_structural_attack_markers(text)
    
    # 5. DESARME DE LÓGICA (Code & Format)
    # Neutralizamos bloques de código y colapsamos espacios para que el 
    # LLM no se distraiga con formatos extraños.
    text = neutralize_code_blocks(text)
    text = normalize_whitespace(text)
    
    return text