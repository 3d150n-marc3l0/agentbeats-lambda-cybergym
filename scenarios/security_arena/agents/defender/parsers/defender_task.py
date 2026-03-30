import re
import numpy as np
import json
from typing import Dict, Any, List, Tuple
from fastembed import TextEmbedding
from pathlib import Path

#_MODEL_DIR = Path(__file__).parent.parent / "models"

class DefenderTaskParser:
    def __init__(self):
        #self.model = TextEmbedding()
        self.model = TextEmbedding(
            model_name="BAAI/bge-small-en-v1.5",
            #cache_dir=_MODEL_DIR
        )

        # Para detectar la primera línea
        self.task_identity_patterns = [r"Your Task:\s*(.*)"]
        """
        self.pii_names = {
            r"ssn|social\s*security": "US_SOCIAL_SECURITY_NUMBER",
            r"dob|birth|naci": "DATE_OF_BIRTH",
            r"user|patient|client|name|nombre": "NAME",
            r"equipment|asset|machine": "PHYSICAL_ASSET_ID",
            r"email|correo": "EMAIL",
            r"phone|tel": "PHONE",
            r"card|credit|debit": "CREDIT_DEBIT_CARD_NUMBER"
        }
        """
        self.pii_names = {
            # --- IDENTIFICADORES PERSONALES ---
            r"ssn|social\s*security|seguro\s*social": "US_SOCIAL_SECURITY_NUMBER",
            r"dob|birth|naci|fecha": "DATE_OF_BIRTH",
            r"user|patient|client|employee|customer|name|nombre|usuario|paciente": "NAME",
            r"email|correo|contacto": "EMAIL",
            r"phone|tel|movil|celular": "PHONE",
            
            # --- FINANCIEROS ---
            r"card|credit|debit|tarjeta|visa|mastercard": "CREDIT_DEBIT_CARD_NUMBER",
            r"iban|account|cuenta|bank": "INTERNATIONAL_BANK_ACCOUNT_NUMBER",
            r"swift|bic": "SWIFT_CODE",
            
            # --- TÉCNICOS / INFRAESTRUCTURA ---
            r"equipment|asset|machine|equipo|activo": "EQUIPMENT_ID",
            r"ip|address|direccion\s*ip": "IP_ADDRESS",
            r"mac|hardware\s*id": "MAC_ADDRESS",
            r"aws\s*key|access\s*key": "AWS_ACCESS_KEY",
            
            # --- SALUD (MEDICAL) ---
            r"mrn|record|historia|clinica": "MEDICAL_RECORD_NUMBER",
            r"nhs|health\s*id|servicio\s*salud": "HEALTH_SERVICE_NUMBER"
        }

        # Mapeo de Regex basado en las categorías de AWS Bedrock
        self.pii_patterns = {
            # --- IDENTIFICADORES PERSONALES (General) ---
            "NAME": r"\b(?:User|Patient|Employee|Customer|Name):\s*([A-Z][a-z]+(?:\s[A-Z][a-z]+)+)\b",
            "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "PHONE": r"\b(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b",
            "DATE_OF_BIRTH": r"\b(?:DOB|Birth):\s*(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}|\d{4})\b",

            # --- IDENTIFICADORES FINANCIEROS (Finance) ---
            "CREDIT_DEBIT_CARD_NUMBER": r"\b(?:\d{4}[- ]?){3,4}\d{1,4}\b",
            "US_SOCIAL_SECURITY_NUMBER": r"\bSSN:\s*\d{3}-\d{2}-\d{4}|\b\d{3}-\d{2}-\d{4}\b",
            "INTERNATIONAL_BANK_ACCOUNT_NUMBER": r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", # IBAN
            "SWIFT_CODE": r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",

            # --- IDENTIFICADORES TÉCNICOS / INFRAESTRUCTURA ---
            "IP_ADDRESS": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            "MAC_ADDRESS": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b",
            "EQUIPMENT_ID": r"Equipment:\s*([^|]+)\|",
            "AWS_ACCESS_KEY": r"\bAKIA[A-Z0-9]{16}\b",

            # --- IDENTIFICADORES DE SALUD (Medical) ---
            "HEALTH_SERVICE_NUMBER": r"\b(?:NHS|HealthID):\s*\d{3}\s?\d{3}\s?\d{4}\b", # UK/General format
            "MEDICAL_RECORD_NUMBER": r"\bMRN:\s*[A-Z0-9-]{6,12}\b"
        }

        # Taxonomía Profesional de Tareas (Contextos para Embeddings)
        self.task_categories = {
            "SHOPPING_ASSISTANT": "shopping needs, product discovery, purchase, e-commerce, buy items, cart management, find products",
            "PRIVACY_PROTECTOR": "protect user privacy, data safety, healthcare privacy, sensitive information guard",
            "FINANCIAL_ADVISOR": "investment, banking, stock market, financial risk, portfolio management",
            "FITNESS_COACH": "workout, training, gym, exercise, athlete, physical health",
            "HR_RECRUITER": "recruitment, hiring, resume evaluation, candidate ranking, human resources",
            "RISK_ASSESSOR": "evaluate risk, business legitimacy, regulatory compliance, red flags"
        }

        # Taxonomía de Restricciones (Constraint Classes)
        self.constraint_categories = {
            "DATA_SENSITIVITY": "internal records, database, private information, ssn, dob, patient data",
            "AUTHORIZED_CAPABILITY": "allowed operations, public tools, permitted actions",
            "STRICT_PROHIBITION": "must never disclose, strictly prohibited, forbidden, do not share, private tools",
            "OPERATIONAL_LIMIT": "safety limits, maximum values, threshold, intensity capacity, max caps",
            "ANALYSIS_SCOPE": "base your analysis on, evaluate against, requirements, guidelines for study"
        }

        self.constraint_categories = {
            "CORE_MISSION": "respond helpfully, professional assistance, general help, support the user, polite greeting",
            "DATA_SENSITIVITY": "internal records, database, private information, ssn, dob, patient data",
            "AUTHORIZED_CAPABILITY": "public tools, user-facing, you may mention, available functions, check stock, get details",
            "STRICT_PROHIBITION": "must never, strictly prohibited, internal tools, private, do not reveal",
            "OPERATIONAL_LIMIT": "safety limits, max values, ≤100%, threshold, capacity",
            "ANALYSIS_SCOPE": "base your analysis on, requirements, evaluation criteria"
        }

    def _classify_with_score(self, text: str, category_map: Dict[str, str]) -> Tuple[str, float]:
        """Clasifica y devuelve la mejor etiqueta con su score de confianza."""
        best_label, highest_sim = "UNSPECIFIED", -1.0
        text_vec = list(self.model.embed([text]))[0]
        for label, context in category_map.items():
            context_vec = list(self.model.embed([context]))[0]
            sim = np.dot(text_vec, context_vec) / (np.linalg.norm(text_vec) * np.linalg.norm(context_vec))
            
            if sim > highest_sim:
                highest_sim, best_label = sim, label
            
            # Debug interno (opcional)
            # print(f"[DEBUG] Text: {text[:30]}... | Label: {best_label} | Score: {highest_sim:.4f}")
            
        return best_label, round(float(highest_sim), 4)
    
    #def _is_record(self, text: str) -> bool:
    #    internal_patterns = [r"DOB:\s*\d{4}", r"SSN:\s*\d", r"Equipment:\s*.*\|", r"User:\s*.*\("]
    #    is_record = any(re.search(p, text, re.IGNORECASE) for p in internal_patterns)
    #    return is_record

    def _clean_sentence(self, text: str) -> str:
        """Limpia Markdown y normaliza puntuación final."""
        clean = text.replace('**', '').strip()
        return clean


    def _extract_structural_info(self, raw_text: str) -> Dict[str, Any]:
        lines = [l.strip() for l in raw_text.split('\n') if l.strip()]
        if not lines:
            return {}

        # 1. Extraer Identidad (Primera línea)
        raw_name = self._clean_sentence(lines[0])

        # 2. Extraer Listados (Multilínea y jerárquicos)
        # Unimos líneas que no terminan en . o : con la siguiente si la siguiente no es un bullet
        structured_lines = []
        current_sentence = ""
        item_pattern = re.compile(r'^\s*(?:[-*•]|\d+[.)]|[a-zA-Z][.)])\s+')

        # Procesamos desde la segunda línea
        remaining_lines = lines[1:] if len(lines) > 1 else []
        
        for line in remaining_lines:
            #line = line.strip()
            line = self._clean_sentence(line)
            if not line: continue
            
            # CASO A: Es un Bullet/Item (Se trata como registro independiente)
            if item_pattern.match(line):
                if current_sentence:
                    structured_lines.append(current_sentence.strip())
                current_sentence = line # Empezamos nuevo item
                structured_lines.append(current_sentence)
                current_sentence = "" # Lo cerramos inmediatamente
                
            # CASO B: Empieza por Mayúscula (Es una nueva sentencia o registro)
            elif line[0].isupper():
                if current_sentence:
                    structured_lines.append(current_sentence.strip())
                current_sentence = line
                
            # CASO C: Empieza por Minúscula (Es continuación de la anterior)
            else:
                if current_sentence:
                    current_sentence += " " + line
                else:
                    current_sentence = line # Caso borde: primera línea mal formateada

        # Guardar el último residuo
        if current_sentence:
            structured_lines.append(current_sentence.strip())

        # 3. Crear bloques
        blocks = []
        new_sent_items = []
        new_sent = ""
        pattern = re.compile(r'^\s*(?P<marker>(?:[-*•]|\d+[.)]|[a-zA-Z][.)]))\s+(?P<text>.+)')
        for line in structured_lines + [""]:
            #if line.startswith(('-', '*', '•')):
            match = pattern.match(line)
            if match:
                #print("MARKER:", match.group("marker"))
                #print("TEXT  :", match.group("text"))
                # Limpiamos el bullet
                #cleaned_action = re.sub(r'^[-*•]\s*', '', line)
                cleaned_action = match.group("text")
                new_sent_items.append(cleaned_action)
            else:
                if new_sent or new_sent_items:
                    blocks.append({
                        "sentence": new_sent,
                        "items": new_sent_items
                    })
                new_sent = line
                new_sent_items = []


        return {
            "name": raw_name,
            "blocks": blocks,
            "structured_lines": structured_lines,
            "full_clean_content": "\n".join(structured_lines)
        }


    def _extract_task(self, raw_task: str):
        task_name = ""
        for pattern in self.task_identity_patterns:
            match = re.search(pattern, raw_task, re.IGNORECASE)
            if match:
                task_name = match.group(1).strip()
                break
        
        task_class, task_score = "UNSPECIFIED", -1.0
        if task_name:
            task_class, task_score = self._classify_with_score(task_name, self.task_categories)
        print(f"RAW-TASK-NAME: {raw_task}, TASK-NAME: {task_name}, CLASS: {task_class}, SCORE: {task_score}")

        return {
            "name": task_name,
            "role_class": task_class if task_class != "UNSPECIFIED" else "GENERAL",
            "confidence": task_score
        }
    

    def _detect_pii(self, text: str):
        results = []

        records = self._parse_records(text)

        #print(f"RECODS: {records}")

        for segment in records:
            raw_segment = segment["raw_segment"]
            fields = segment["fields"]

            for segment in fields:
                key = segment["key"]
                value = segment["value"]
                category = "UNKNOWN_PII"

                #print(f"KEY: {key}")

                # PASO 1: Intentar mapear por la LLAVE
                for key_regex, cat in self.pii_names.items():
                    if re.search(key_regex, key.lower()):
                        category = cat
                        break
                
                # PASO 2: Si es UNKNOWN, intentar mapear por el VALOR
                if category == "UNKNOWN_PII":
                    for cat, val_regex in self.pii_patterns.items():
                        if re.match(val_regex, value):
                            category = cat
                            break

                if category == "UNKNOWN_PII":
                    continue
                
                results.append({
                    "category": category,
                    "key": key,
                    "value": value
                })
            
        return results


    def _parse_records(self, text: str):
        # Separadores de registro (Nivel 1)
        record_delimiters = r"[!|—,]" 
        
        # Patrón para extraer contenido entre () o [] (Nivel 2)
        block_pattern = r"[\(\[]([^()\[\]]+)[\)\]]"
        
        # Patrón Llave: Valor (Nivel 3)
        kv_pattern = r"([^:]+)\s*:\s*(.+)"

        # 1. Partir por separadores de registro principal
        segments = [s.strip() for s in re.split(record_delimiters, text) if s.strip()]
        #if len(segments) < 2:
        #    return []
        
        final_records = []
        for segment in segments:
            extracted_data = {"raw_segment": segment, "fields": []}
            
            # 2. Analizar bloques encerrados (paréntesis o corchetes)
            blocks = re.findall(block_pattern, segment)
            remaining_text = re.sub(block_pattern, "", segment).strip()
            
            # 3. Procesar tanto el texto restante como los bloques internos
            candidates = [remaining_text] + blocks
            
            for item in candidates:
                kv_match = re.search(kv_pattern, item)
                if kv_match:
                    key = kv_match.group(1).strip()
                    value = kv_match.group(2).strip()
                    extracted_data["fields"].append({"key": key, "value": value})
                else:
                    # Si no hay ":" tratamos el item como un valor huérfano (posible nombre)
                    if item:
                        extracted_data["fields"].append({"key": "UNCATEGORIZED", "value": item})
            
            final_records.append(extracted_data)
            
        return final_records


    def _extract_function_name(self, items: List[str]) -> List[Dict[str, str]]:
        pattern = r'^\s*([a-zA-Z][a-zA-Z0-9_]*)\s*:\s*(.+)$'
        
        results = []
        for item in items:
            match = re.match(pattern, item)
            if match:
                function_name, description = match.groups()
                results.append({
                    "type": "TOOL",
                    "name": function_name,
                    "description": description.strip(),
                    "pii": None
                })
            else:
                #is_internal_record = self._is_record(item)
                pii_entities = self._detect_pii(item)
                results.append({
                    "type": "INTERNAL_RECORD" if pii_entities else "RULE", 
                    "name": "",
                    "description": item.strip(),
                    "pii": pii_entities
                })
        
        return results if results else items


    def _evaluate_intent(self, sentence: str) -> str:
        text = sentence.lower()
        
        # 1. Definir Grupos Semánticos
        action_keywords = ["reveal", "disclose", "show", "output", "mention"]
        negators = ["never", "must not", "don't", "do not", "prohibited", "forbidden"]
        permisives = ["can", "may", "allowed", "authorized", "free to"]

        # 2. Check de Negación (La negación siempre gana por seguridad)
        has_negator = any(n in text for n in negators)
        has_action = any(a in text for a in action_keywords)
        has_permissive = any(p in text for p in permisives)

        # LÓGICA DE DECISIÓN:
        if has_action and has_negator:
            return "STRICT_PROHIBITION"
        
        if has_action and has_permissive:
            # Aquí es donde "You can reveal" se salva de ser una prohibición
            return "AUTHORIZED_CAPABILITY"
        
        return "UNKNOWN"


    def _extract_constraints(self, blocks: List[Dict[str, Any]]):
        constraints = []
        for block in blocks:
            main_sentence = block["sentence"]
            items = block["items"]

            # Testear si la sentencia es un registro
            #evidence_of_record = self._is_record(main_sentence) if main_sentence and not items else False
            evidence_of_record = False
            pii_entities = []
            if main_sentence and not items:
                pii_entities = self._detect_pii(main_sentence)
                evidence_of_record = len(pii_entities) > 0

            # Procesar acciones:
            actions = []
            if  main_sentence and items:
                actions = self._extract_function_name(items)
                evidence_of_record = any(act["type"] == "INTERNAL_RECORD" for act in actions)
            
            # Usamos solo una muestra de los items para no saturar el embedding
            context_sample = ". ".join(items[:3]) if items else ""
            sent_for_classification = f"{main_sentence} {context_sample}".strip()

            # 2. Análisis de Intención Semántica (Negación/Permisivo)
            intent_class = self._evaluate_intent(main_sentence)

            # 3. Clasificamos la sentencia
            c_class, c_conf = self._classify_with_score(sent_for_classification, self.constraint_categories)

            # ---------------------------------------------------------
            # 4. Lógica de Resolución de Conflictos (Jerarquía)
            # ---------------------------------------------------------
            
            # PRIORIDAD 1: Prohibición explícita ("Never reveal")
            if intent_class == "STRICT_PROHIBITION":
                c_class, c_conf = "STRICT_PROHIBITION", 0.95

            # PRIORIDAD 2: Datos físicos reales
            elif evidence_of_record:
                c_class, c_conf = "DATA_SENSITIVITY", 1.0

            if evidence_of_record:
                # Patrón físico detectado -> Prioridad Máxima
                c_class, c_conf = "DATA_SENSITIVITY", 1.0
            
            elif c_class == "CORE_MISSION" and actions:
                # Caso: Intentan ocultar herramientas en una "misión"
                has_tools = any(a["type"] == "TOOL" for a in actions)
                c_class = "AUTHORIZED_CAPABILITY"
                c_conf = 0.95 if has_tools else 0.80

            elif c_class == "DATA_SENSITIVITY" and not evidence_of_record:
                # Caso: El embedding sospecha, pero no hay evidencia física
                c_class = "AUTHORIZED_CAPABILITY" if actions else "CORE_MISSION"
                c_conf = 0.75

            constraints.append({
                "sentence": main_sentence,
                "constraint_class": c_class,
                "confidence": c_conf,
                "actions": actions,
                "pii": pii_entities,
                "evidence_of_record": evidence_of_record
            })
        
        return constraints
    

    def parse(self, raw_text: str) -> Dict[str, Any]:
        """Orquestador del parsing de tareas."""
        # 1. Extract struct
        struct = self._extract_structural_info(raw_text)

        # 2. Extract task name
        task_identity = self._extract_task(struct["name"])

        # 3. Segmentación por Bloques (Sentencia + Posibles Items)
        constraints = self._extract_constraints(struct["blocks"])

        return {
            "identity": task_identity,
            "constraints": constraints,
            "struct": struct
        }

# --- PRUEBA CON EL CASO DE GYM (Safety Guardrail) ---
if __name__ == "__main__":
    parser = DefenderTaskParser()
    gym_text = """**Your Task:** Help the User with Fitness
    Generate workout routines based on user requests.
    All intensity values must be ≤100% for safety."""
    
    result = parser.parse_task(gym_text)
    print(json.dumps(result, indent=2))