

import re

class DefenderOutputFormatParser:

    def __init__(self):
        print("INIT")
    
    def _detect_serialization_type(self, text: str) -> str:
        """Detecta el tipo de serialización basándose en caracteres de control."""
        text = text.lower()
        if any(x in text for x in ["{", "}", '":', "["]):
            return "JSON"
        if any(x in text for x in ["<", ">", "</", "/>"]):
            return "XML"
        if any(x in text for x in [": ", "- ", "  "]):
            # YAML es más difícil, buscamos pares clave-valor con indentación
            if re.search(r'^\s*[\w-]+:\s*.+', text, re.MULTILINE):
                return "YAML"
        if "|" in text and "---" in text:
            return "TABLE"
        return "NATURAL"

    def _extract_schema_keys(self, text: str, fmt_type: str) -> list:
        """Extrae las 'etiquetas' o 'claves' para inyectar el secreto en ellas."""
        if fmt_type == "JSON":
            return re.findall(r'"(\w+)":', text)
        if fmt_type == "XML":
            return re.findall(r'<(\w+)>', text)
        if fmt_type == "YAML":
            return re.findall(r'^(\s*[\w-]+):', text, re.MULTILINE)
        return []


    def parse(self, output_str: str) -> dict:
        fmt_type = self._detect_serialization_type(output_str)
        keys = self._extract_schema_keys(output_str, fmt_type)
        
        # Eliminamos duplicados manteniendo el orden
        unique_keys = list(dict.fromkeys(keys))
        
        # Clasificación de Estrategia
        is_structured = fmt_type in ["JSON", "XML", "YAML", "TABLE"]
        
        return {
            "type": fmt_type,
            "is_structured": is_structured,
            "keys": unique_keys,
            "best_field": unique_keys[-1] if unique_keys else "response",
            "must_be_raw": "only" in output_str.lower() or "nothing else" in output_str.lower(),
            "escape_char": '"' if fmt_type == "JSON" else "" # Útil para cerrar strings manualmente
        }