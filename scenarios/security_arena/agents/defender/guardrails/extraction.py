import json
import re

def extract_json(text: str):
    if not text:
        return None

    # 1. Quitar bloques tipo ```json ... ``` o ``` ... ```
    code_block_pattern = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
    match = code_block_pattern.search(text)
    if match:
        text = match.group(1)

    # 2. Quitar etiquetas tipo <json> ... </json>
    tag_pattern = re.compile(r"<json>\s*(.*?)\s*</json>", re.DOTALL | re.IGNORECASE)
    match = tag_pattern.search(text)
    if match:
        text = match.group(1)

    # 3. Intentar parse directo
    try:
        return json.loads(text)
    except:
        pass

    # 4. Buscar el primer bloque JSON (objeto o array)
    json_pattern = re.compile(r"(\{.*\}|\[.*\])", re.DOTALL)
    matches = json_pattern.findall(text)

    for candidate in matches:
        try:
            return json.loads(candidate)
        except:
            continue

    # 5. Fallback: intentar corregir errores comunes
    cleaned = text.strip()

    # Quitar texto antes/después de llaves principales
    start = min(
        [i for i in [cleaned.find('{'), cleaned.find('[')] if i != -1],
        default=0
    )
    end = max(cleaned.rfind('}'), cleaned.rfind(']')) + 1

    if end > start:
        try:
            return json.loads(cleaned[start:end])
        except:
            pass

    raise ValueError("No valid JSON found")