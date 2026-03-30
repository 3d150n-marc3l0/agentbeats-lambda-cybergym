import base64
import re

def decode_and_normalize_payloads(text: str) -> str:
    """Detecta y decodifica Base64 o Hexadecimal incrustado."""

    # Regex para Base64 (mínimo 12 caracteres para evitar falsos positivos con palabras cortas)
    #b64_pattern = r'(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    #b64_pattern = r'\b(?:[A-Za-z0-9+/]{4}){4,}(?:==|=)?\b'
    #b64_pattern = r'\b(?:[A-Za-z0-9+/]{4}){3,500}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b'
    #b64_pattern = r'(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    #b64_pattern = r'(?:[A-Za-z0-9+/]{4}\s*){4,}(?:[A-Za-z0-9+/]{2,3}=?)?'
    b64_pattern = r'\b(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2,3}=?)?\b'
    
    def b64_replacer(match):
        try:
            candidate = match.group(0)
            # Añadir padding si falta para evitar errores de decodificación [REVIEW]
            missing_padding = len(candidate) % 4
            if missing_padding:
                candidate += '=' * (4 - missing_padding)
            
            decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
            # Solo lo reemplazamos si el resultado parece texto legible (letras/espacios)
            #if any(c.isalpha() for c in decoded):
            #    return f" [DECODED_START] {decoded} [DECODED_END] "
            
            # Validar que al menos la mitad son caracteres imprimibles
            printable_chars = sum(1 for c in decoded if c.isprintable() or c.isspace())
            if printable_chars / max(len(decoded), 1) >= 0.5:
                #return f" [DECODED_START] {decoded} || {candidate} {missing_padding} [DECODED_END] "
                #return f" [DECODED_START] {decoded} [DECODED_END] "
                return " [REDACTED_B64] "
            
            return candidate
            
        except:
            return match.group(0)

    # 1. Intentar decodificar Base64
    #text = re.sub(b64_pattern, b64_replacer, text)
    
    # 2. Intentar decodificar Hexadecimal (ej: \x48\x65\x6c\x6c\x6f)
    #hex_pattern = r'(?:\\x[0-9a-fA-F]{2})+'
    hex_pattern = r'\b(?:\\x[0-9a-fA-F]{2})+\b'
    hex_pattern = r'(?:\\x[0-9a-fA-F]{2}){2,500}|(?:\b0x[0-9a-fA-F]{2,1000}\b)'
    def hex_replacer(match):
        try:
            hex_val = match.group(0).replace('\\x', '')
            decoded = bytes.fromhex(hex_val).decode('utf-8', errors='ignore')
            printable_chars = sum(1 for c in decoded if c.isprintable() or c.isspace())
            #return f" [HEX_DECODED] {decoded} "
            if printable_chars / max(len(decoded), 1) >= 0.5:
                #return f" [HEX_DECODED_START] {decoded} [HEX_DECODED_END] "
                return f" [REDACTED_HEX] "
            return hex_val
        except:
            return match.group(0)
            
    #text = re.sub(hex_pattern, hex_replacer, text)

    # ORDEN CRÍTICO: 
    # 1. Limpiar/Decodificar Base64 primero.
    text = re.sub(b64_pattern, b64_replacer, text)
    
    # 2. Luego buscar Hex en lo que queda.
    text = re.sub(hex_pattern, hex_replacer, text)
    
    return text