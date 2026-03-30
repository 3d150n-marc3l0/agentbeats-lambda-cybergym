import unicodedata
import re

def normalize_unicode(text: str) -> str:
    """Convierte caracteres visualmente similares (homógrafos) a su forma estándar."""
    # NFKC es vital para que una 'a' cirílica se convierta en una 'a' latina si es posible,
    # o al menos para normalizar formas compuestas.
    return unicodedata.normalize('NFKC', text)

def remove_control_chars_old(text: str) -> str:
    """Elimina caracteres invisibles, zero-width spaces y control ASCII."""
    # Filtra caracteres de control (Cc) y otros no imprimibles (Cf, Cs, Co, Cn)
    return "".join(ch for ch in text if unicodedata.category(ch)[0] != "C")

def remove_control_chars(text: str) -> str:
    """
    Elimina caracteres de control peligrosos pero PRESERVA 
    saltos de línea, retornos de carro y tabulaciones.
    """
    # Definimos lo que queremos mantener explícitamente
    # \n (Line Feed), \r (Carriage Return), \t (Tab)
    whitelisted_controls = {'\n', '\r', '\t'}
    
    # Reconstruimos el texto filtrando caracteres de categoría "C" (Control)
    # pero saltándonos nuestra lista blanca.
    cleaned = "".join(
        ch for ch in text 
        if unicodedata.category(ch)[0] != "C" or ch in whitelisted_controls
    )
    
    # 2. Protección contra "Backspaces" y caracteres de sobreimpresión
    # Algunos atacantes usan \b (backspace) para ocultar texto a humanos
    # pero que el LLM sí procesa. Aquí los eliminamos por completo.
    cleaned = cleaned.replace('\b', '')
    
    return cleaned

def normalize_whitespace(text: str) -> str:
    """Colapsa múltiples espacios y saltos de línea para evitar 'Prompt Displacement'."""
    # El atacante puede meter 1000 espacios para empujar tus instrucciones fuera de la ventana.
    text = re.sub(r'\s+', ' ', text)
    return text.strip()