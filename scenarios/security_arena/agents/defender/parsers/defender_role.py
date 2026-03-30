import re

class DenfenderRoleParser2:
    def __init__(self):
        # Esquema base para garantizar el Contrato Común
        self.default_contract = {
            "identity": {"name": None, "role_class": "GENERAL", "authority_level": "ASSISTANT"},
            "constraints": {"hard_limits": [], "data_sources": [], "forbidden_actions": []},
            "context_entities": {"target_subject": None, "specialized_equipment": None, "required_tone": "NEUTRAL"},
            "risk_profile": {"primary_threat": "UNSPECIFIED", "criticality": "MEDIUM", "compliance_tags": []}
        }

    def parse(self, role_text: str) -> dict:
        ctx = self.default_contract.copy()
        role_lower = role_text.lower()

        # 1. Extraer Identidad y Clase
        ctx["identity"]["name"] = self._extract_regex(role_text, r"Role:\s*([^\n|]+)")
        ctx["identity"]["role_class"] = self._detect_class(role_lower)
        
        # 2. Extraer Límites Numéricos (como el 100% de intensidad)
        limits = re.findall(r"(\w+)\s*limit:\s*(\d+)\s*([\w%]+)", role_text, re.IGNORECASE)
        for metric, value, unit in limits:
            ctx["constraints"]["hard_limits"].append({
                "metric": metric.lower(),
                "value": int(value),
                "unit": unit
            })

        # 3. Entidades de Contexto (Sujetos y Equipos)
        ctx["context_entities"]["target_subject"] = self._extract_regex(role_text, r"User:\s*([^\n|)]+)")
        ctx["context_entities"]["specialized_equipment"] = self._extract_regex(role_text, r"Equipment:\s*([^\n|]+)")

        # 4. Compliance y Riesgo
        if "hipaa" in role_lower:
            ctx["risk_profile"]["compliance_tags"].append("HIPAA")
            ctx["risk_profile"]["primary_threat"] = "DATA_LEAK_PII"
            ctx["risk_profile"]["criticality"] = "HIGH"
        
        if "safety-critical" in role_lower:
            ctx["risk_profile"]["primary_threat"] = "PHYSICAL_SAFETY"
            ctx["risk_profile"]["criticality"] = "CRITICAL"

        # 5. Acciones Prohibidas (Basado en verbos comunes de restricción)
        if "strictly follow" in role_lower or "bound by" in role_lower:
            ctx["constraints"]["forbidden_actions"].append("OUT_OF_SOURCE_INSTRUCTION")

        return ctx

    def _extract_regex(self, text, pattern):
        match = re.search(pattern, text)
        return match.group(1).strip() if match else None

    def _detect_class(self, text: str) -> str:
        # Definimos los "Lexicones" con sinónimos y términos contextuales
        lexicons = {
            "MEDICAL": {
                "keywords": ["patient", "doctor", "hipaa", "medical", "health", "clinical", "appointment", "staff", "hospital"],
                "weight": 1.0
            },
            "FITNESS": {
                "keywords": ["coach", "fitness", "workout", "gym", "intensity", "equipment", "athlete", "training", "exercise"],
                "weight": 1.0
            },
            "FINANCE": {
                "keywords": ["investment", "advisor", "financial", "market", "risk", "business", "fundamental", "portfolio", "stock"],
                "weight": 1.0
            },
            "HR": {
                "keywords": ["talent", "evaluator", "candidate", "resume", "hiring", "recruitment", "job description", "files"],
                "weight": 1.0
            },
            "PSYCHOLOGY": {
                "keywords": ["emotional", "mental", "therapy", "psychological", "feeling", "well-being", "mindset", "support"],
                "weight": 1.2 # Le damos un poco más de peso para diferenciarlo de un coach deportivo
            }
        }

        scores = {domain: 0 for domain in lexicons}

        # Contribución de cada palabra encontrada
        words = text.split()
        for word in words:
            clean_word = word.strip(".,:;()").lower()
            for domain, data in lexicons.items():
                if clean_word in data["keywords"]:
                    scores[domain] += data["weight"]

        # Si hay empate o puntuación muy baja, devolvemos GENERAL
        max_score = max(scores.values())
        if max_score < 1:
            return "GENERAL"
        
        # Retornamos el dominio con más "votos"
        return max(scores, key=scores.get)
    

import re
import numpy as np
import json
from typing import Dict, Any, List, Tuple, Set
from fastembed import TextEmbedding

class DefenderRoleParser:
    def __init__(self):
        # Cargamos el modelo una sola vez en el constructor
        self.model = TextEmbedding()

        # Para detectar la primera línea
        self.role_identity_patterns = [r"Your Role:\s*(.*)", r"You are a\s*(.*)"]

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
        
        # Configuraciones de categorías (Centroides Semánticos)
        self.domains = {
            # Añadimos términos transaccionales fuertes que lo alejen de 'General'
            "E_COMMERCE": "e-commerce shopping cart webstore checkout purchase transaction retail storefront sku shopify",
            # Reducimos 'General' a términos que solo se usen cuando no hay intención clara
            "GENERAL": "generic-task simple-help untyped-assistant basic-information multipurpose",
            "MEDICAL_HEALTH": "healthcare medical patient diagnosis hospital HIPAA clinic doctor",
            "FITNESS_NUTRITION": "workout training exercise gym fitness athlete coach sports",
            "FINANCIAL_SERVICES": "banking investment money finance trading stock market accounting",
            "HR_RECRUITMENT": "human resources recruiting hiring employee payroll workplace onboarding",
            "PSYCHOLOGY": "mental health therapy psychology counseling therapist psychiatrist",
            "CHEMISTRY": "chemistry chemical laboratory molecules reaction science lab",
            #"E_COMMERCE": "shopping retail order shipping checkout storefront catalog refund customer store",
            #"GENERAL": "general purpose assistant common tasks help information"
        }

        # Taxonomía de Restricciones (Constraint Classes)
        self.constraint_categories = {
            "CORE_MISSION": "respond helpfully, professional assistance, general help, support the user, polite greeting",
            "DATA_SENSITIVITY": "internal records, database, private information, ssn, dob, patient data",
            "AUTHORIZED_CAPABILITY": "allowed operations, public tools, permitted actions",
            "STRICT_PROHIBITION": "must never disclose, strictly prohibited, forbidden, do not share, private tools",
            "OPERATIONAL_LIMIT": "safety limits, maximum values, threshold, intensity capacity, max caps",
            "ANALYSIS_SCOPE": "base your analysis on, evaluate against, requirements, guidelines for study"
        } 
        
        self.risks_seeds = {
            "DATA_LEAK_PII": "personally identifiable information patient records private data credentials HIPAA PII",
            "PHYSICAL_SAFETY": "dosage limits physical danger training maximums safety boundaries harmful instructions",
            "UNSPECIFIED": "standard interaction low risk no sensitive data generic help"
        }

        self.data_source_contexts = {
            "DOCUMENT_INPUT": "analyze files, read documents, evaluate candidates in files, financial reports, uploaded pdf"
        }
    
    def _classify_with_score(self, text: str, category_map: Dict[str, str]) -> tuple:
        """Devuelve la categoría y su puntuación de confianza."""
        text_vec = list(self.model.embed([text]))[0]
        best_cat = "UNSPECIFIED"
        highest_sim = -1.0
        
        for category, context in category_map.items():
            context_vec = list(self.model.embed([context]))[0]
            sim = np.dot(text_vec, context_vec) / (np.linalg.norm(text_vec) * np.linalg.norm(context_vec))
            if sim > highest_sim:
                highest_sim = sim
                best_cat = category

        return best_cat, round(float(highest_sim), 4) 
    

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
        """
        lines = lines[1:] if len(lines) > 1 else lines
        for line in lines:
            line = self._clean_sentence(line)
            if item_pattern.match(line):
            #if line.startswith(('-', '*', '•')):
                if current_sentence:
                    structured_lines.append(current_sentence)
                    current_sentence = ""
                structured_lines.append(line)
            else:
                if current_sentence:
                    current_sentence += " " + line
                else:
                    current_sentence = line
                
                if current_sentence.endswith(('.', ':')):
                    structured_lines.append(current_sentence)
                    current_sentence = ""
        if current_sentence:
            structured_lines.append(current_sentence)
        """
        # Procesamos desde la segunda línea
        remaining_lines = lines[1:] if len(lines) > 1 else []
        
        for line in remaining_lines:
            line = line.strip()
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

        # 3. Blocks
        blocks = []
        new_sent_items = []
        new_sent = ""
        pattern = re.compile(r'^\s*(?P<marker>(?:[-*•]|\d+[.)]|[a-zA-Z][.)]))\s+(?P<text>.+)')
        for line in structured_lines + [""]:
            #if line.startswith(('-', '*', '•')):
            match = pattern.match(line)
            if match:
                # Limpiamos el bullet
                #cleaned_action = re.sub(r'^[-*•]\s*', '', line)
                #required_actions.append(cleaned_action)
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


    def _extract_role(self, raw_role: str):
        role_name = ""
        for pattern in self.role_identity_patterns:
            match = re.search(pattern, raw_role, re.IGNORECASE)
            if match:
                role_name = match.group(1).strip()
                break
        
        role_class, role_score = "UNSPECIFIED", -1.0
        if role_name:
            role_class, role_score = self._classify_with_score(role_name, self.domains)
        print(f"RAW-TASK-NAME: {raw_role}, TASK-NAME: {role_name}, CLASS: {role_class}, SCORE: {role_score}")

        return {
            "name": role_name,
            "role_class": role_class if role_class != "UNSPECIFIED" else "GENERAL",
            "confidence": role_score
        }

    def _extract_hard_limits(self, text: str) -> List[str]:
        """
        Detecta restricciones críticas en inglés: 
        Límites de tiempo, intentos, presupuesto o seguridad física.
        """
        limit_patterns = [
            r"(?:limit|maximum|max|threshold|cap|quota):\s*[\w\d\s\/\%\.]+", 
            r"\d+\s*(?:days|attempts|hours|tries|usd|euro|kg|mg|units)",
            r"no more than\s*\d+",
            r"must not exceed\s*\d+",
            r"strictly prohibited to\s*.*"
        ]
        found_limits = []
        for p in limit_patterns:
            matches = re.findall(p, text, re.IGNORECASE)
            found_limits.extend([m.strip() for m in matches])
        
        # Eliminamos duplicados y limpiamos puntuación final
        return list(set([l.rstrip('.:') for l in found_limits]))
    
    def _extract_data_sources(self, text: str) -> List[str]:
        sources = ["PLAIN_TEXT_INPUT"]
        # Semántica para documentos
        doc_cat, score = self._classify_with_score(text, self.data_source_contexts)
        if doc_cat == "DOCUMENT_INPUT" and score > 0.4:
            sources.append("DOCUMENT_INPUT")
        
        # RegEx para registros internos (PII / Equipos)
        internal_patterns = [r"DOB:\s*\d{4}", r"SSN:\s*\d", r"Equipment:\s*.*\|", r"User:\s*.*\("]
        if any(re.search(p, text, re.IGNORECASE) for p in internal_patterns):
            sources.append("INTERNAL_RECORD")
            
        return sources
    
    
    #def _is_record(self, text: str) -> bool:
    #    internal_patterns = [r"DOB:\s*\d{4}", r"SSN:\s*\d", r"Equipment:\s*.*\|", r"User:\s*.*\("]
    #    is_record = any(re.search(p, text, re.IGNORECASE) for p in internal_patterns)
    #    return is_record
    
    #def _detect_pii2(self, text: str) -> dict:
    #    """Retorna un diccionario con las entidades encontradas y su categoría."""
    #    detections = {}
    #    for category, pattern in self.pii_patterns.items():
    #        matches = re.findall(pattern, text, re.IGNORECASE)
    #        if matches:
    #            # Limpiamos los matches si son tuplas (en el caso de grupos de captura)
    #            detections[category] = [m if isinstance(m, str) else m[0] for m in matches]
    #    return detections
    
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
                "pii": pii_entities
            })
        return constraints


    def _extract_risk_profiles(self, text: str, data_sources: List[str]) -> List[Dict[str, Any]]:
        risk_profiles = []
        possible_threats: Set[str] = set()
        
        # 1. Amenaza detectada por IA
        primary_threat, primary_threat_score = self._classify_with_score(text, self.risks_seeds)
        if primary_threat != "UNSPECIFIED":
            possible_threats.add((primary_threat, primary_threat_score))
        
        # 2. Mapeo basado en fuentes de datos (Inferencia de Seguridad)
        if "INTERNAL_RECORD" in data_sources:
            possible_threats.add(("DATA_LEAK_PII", 1.0))
        
        if "DOCUMENT_INPUT" in data_sources:
            possible_threats.add(("INDIRECT_PROMPT_INJECTION", 0.5))

        # 3. Construcción de perfiles
        for threat, threat_score in possible_threats:
            # Determinamos criticidad: PII e Injection siempre son HIGH
            is_high = threat in ["DATA_LEAK_PII", "INDIRECT_PROMPT_INJECTION", "PHYSICAL_SAFETY"]
            
            risk_profiles.append({
                "primary_threat": threat,
                "confidence": threat_score,
                "criticality": "HIGH" if is_high else "LOW",
                "compliance_tags": ["HIPAA"] if "HIPAA" in text.upper() else []
            })
        
        if not risk_profiles:
            risk_profiles.append({"primary_threat": "UNSPECIFIED", "criticality": "LOW", "compliance_tags": []})
            
        return risk_profiles
    

    def parse(self, raw_text: str) -> Dict[str, Any]:
        """Orquestador principal."""
        # 1. Fase Estructural
        struct = self._extract_structural_info(raw_text)

        # 2. Extract role name
        role_identity = self._extract_role(struct["name"])

        # 3. Extract data sources
        data_sources = self._extract_data_sources(struct["full_clean_content"])

        # 4. Extract Risk
        risk_profiles = self._extract_risk_profiles(struct["full_clean_content"], data_sources)
        
        # 5. Extract contraints
        constraints= self._extract_constraints(struct["blocks"])
        
        # 4. Construcción del Diccionario Final
        return {
            "identity": role_identity,
            "constraints": constraints,
            "data_sources": data_sources,
            "risk_profile": risk_profiles,
            "struct": struct
        }






# --- TEST ---
if __name__ == "__main__":
    text = """**Your Role:** HIPAA-Compliant Medical Chatbot
    You help with:
    - Scheduling appointments
    - Looking up records
    Bound by HIPAA."""
    
    parser = DefenderRoleParser()
    print(json.dumps(parser.parse(text), indent=2))    