"""
AI-анализатор для Cyber Garden 2026.
Принимает находки от сканеров, возвращает ТРИ отчёта:
  - summary: короткое саммари (самый капец)
  - text: полный текстовый отчёт (для Telegraph)
  - json: JSON для интеграции (дашборды)

Провайдер выбирается пользователем:
  - yandex  — облако YandexGPT
  - ollama  — локальная модель (закрытый контур)

Если ИИ сломался или вернул мусор — активируется Python-фоллбэк.
"""
import os
import json
import re
import httpx
from config import logger


SECRET_CLASSES = {
    "password": "Встроенный пароль",
    "api-key": "Встроенный ключ API",
    "configuration-token": "Токен в конфигурации",
    "secret-fallback": "Встроенный секрет, используемый по умолчанию",
    "recoverable-token": "Токен, восстанавливаемый из исходников",
}

SAST_CLASSES = {
    "sql-injection": "SQL-инъекция",
    "tls-verification": "Ослабленная проверка TLS",
    "credentialed-cors": "Излишне широкий CORS с учётными данными",
    "route-authorization": "Ошибка проверки доступа к маршруту",
    "object-authorization": "Ошибка проверки доступа к объекту",
}


class AIAnalyzer:
    def __init__(self, provider: str = None, ollama_url: str = None,
                 ollama_model: str = None):
        self.provider = provider or os.getenv("DEFAULT_PROVIDER", "yandex")
        self.yandex_token = os.getenv("YANDEX_IAM_TOKEN")
        self.yandex_folder_id = os.getenv("YANDEX_FOLDER_ID")
        self.ollama_url = ollama_url or os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.ollama_model = ollama_model or os.getenv("OLLAMA_MODEL", "qwen2.5-coder:3b")
        logger.info(f"✅ Провайдер выбран пользователем: {self.provider}")

    async def analyze_and_return(self, all_findings: dict) -> dict:
        """Возвращает: summary (коротко) + text (полный) + json (для интеграции)."""
        if not all_findings:
            return {
                "summary": "🔍 Уязвимостей не найдено ✅",
                "text": "🔍 Уязвимостей не найдено ✅",
                "json": {"findings": []}
            }

        grouped = self._group_by_type(all_findings)
        summary = self._generate_summary(all_findings, grouped)
        text_report = await self._generate_text_report(all_findings, grouped)
        json_report = self._generate_json_report(all_findings, grouped)
        
        return {"summary": summary, "text": text_report, "json": json_report}

    def _group_by_type(self, findings: dict) -> dict[str, dict]:
        grouped: dict[str, dict] = {}
        for fid, data in findings.items():
            ftype = data.get("type", "unknown")
            if ftype not in grouped:
                grouped[ftype] = {}
            grouped[ftype][fid] = data
        return grouped

    def _generate_summary(self, all_findings: dict, grouped: dict[str, dict]) -> str:
        """Короткое саммари: общий капец + топ-3 критичных находки."""
        total = len(all_findings)
        
        by_priority = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for fid, data in all_findings.items():
            p = data.get("priority", "MEDIUM").upper()
            if p not in by_priority:
                by_priority[p] = []
            by_priority[p].append((fid, data))
        
        cat_stats = ", ".join(f"{t.upper()}: {len(items)}" for t, items in grouped.items())
        
        top_findings = []
        for priority in ["CRITICAL", "HIGH"]:
            for fid, data in by_priority.get(priority, []):
                loc = data.get("locate", [{}])[0]
                ftype = data.get("type", "unknown")
                file_short = loc.get("file", "unknown").split("/")[-1]
                line = loc.get("line", "?")
                
                if ftype == "secrets":
                    desc = f"захардкоженный секрет в {file_short}:{line}"
                elif ftype == "sca":
                    cve = data.get("advisoryIds", ["?"])[0]
                    desc = f"уязвимая библиотека ({cve})"
                elif ftype == "logic":
                    code = loc.get("code", "").lower()
                    if "select " in code or "sql" in code:
                        desc = f"SQL-инъекция в {file_short}:{line}"
                    elif "hostnameverifier" in code:
                        desc = f"обход TLS в {file_short}:{line}"
                    elif "permitall" in code:
                        desc = f"открытый маршрут в {file_short}:{line}"
                    else:
                        desc = f"уязвимость в {file_short}:{line}"
                else:
                    desc = f"находка в {file_short}:{line}"
                
                top_findings.append((priority, fid, desc))
                if len(top_findings) >= 3:
                    break
            if len(top_findings) >= 3:
                break
        
        lines = [f"🔍 Cyber Garden — КРАТКИЙ ОТЧЁТ", f"Всего находок: {total} ({cat_stats})\n"]
        
        crit = len(by_priority.get("CRITICAL", []))
        high = len(by_priority.get("HIGH", []))
        
        if crit > 0:
            lines.append(f"🚨 КРИТИЧНЫХ: {crit} — требуется немедленное вмешательство!")
        elif high > 0:
            lines.append(f"⚠️ Серьёзных: {high} — нужно исправить до релиза")
        else:
            lines.append(f"✅ Критичных нет, но есть {total} замечаний")
        
        if top_findings:
            lines.append("\n🔴 ТОП ПРОБЛЕМ:")
            for i, (p, fid, desc) in enumerate(top_findings, 1):
                lines.append(f"  {i}. [{p}] {desc}")
        
        return "\n".join(lines)

    async def _generate_text_report(self, all_findings: dict, grouped: dict[str, dict]) -> str:
        prompt = self._build_prompt(all_findings, grouped)
        ai_text = ""

        try:
            if self.provider == "yandex":
                ai_text = await self._call_yandex(prompt)
            elif self.provider == "ollama":
                ai_text = await self._call_ollama(prompt)
            else:
                logger.warning(f"⚠️ Неизвестный провайдер: {self.provider}. Фоллбэк.")
        except Exception as e:
            logger.warning(f"⚠️ Ошибка LLM ({self.provider}): {e}. Активирую Python-фоллбэк.")

        if not ai_text or self._is_bad_response(ai_text):
            logger.warning("⚠️ ИИ выдал некорректный формат. Активирую Python-фоллбэк.")
            return self._python_fallback_text(all_findings, grouped)

        return self._validate(ai_text, all_findings)

    def _detect_class(self, ftype: str, data: dict, loc: dict) -> str:
        code = loc.get("code", "").lower()
        file_path = loc.get("file", "").lower()

        if ftype == "secrets":
            if any(kw in code for kw in ["password", "pass=", "passwd", "db_pass", "db_password"]):
                return "password"
            if any(kw in code for kw in ["api-key", "api_key", "apikey", "x-api-key"]):
                return "api-key"
            if any(kw in file_path for kw in [".yml", ".yaml", ".properties", ".conf", "config"]):
                return "configuration-token"
            if any(kw in code for kw in ["token", "jwt", "bearer"]):
                return "recoverable-token"
            return "secret-fallback"

        elif ftype == "logic":
            if any(kw in code for kw in ["sql", "select ", "insert ", "update ", "delete ", "from "]):
                return "sql-injection"
            if any(kw in code for kw in ["hostnameverifier", "tls", "ssl", "sethostnameverifier"]):
                return "tls-verification"
            if any(kw in code for kw in ["cors", "allowedorigin", "allowedoriginpatterns"]):
                return "credentialed-cors"
            if any(kw in code for kw in ["permitall", "requestmatchers", "antmatchers"]):
                return "route-authorization"
            if any(kw in code for kw in ["findbyid", "findby", "getbyid", "repository."]):
                return "object-authorization"
            return "sql-injection"

        return ""

    def _generate_json_report(self, all_findings: dict, grouped: dict[str, dict]) -> dict:
        findings_array = []
        category_map = {"secrets": "SECRET", "sca": "SCA", "logic": "SAST"}

        for fid, data in all_findings.items():
            ftype = data.get("type", "unknown")
            category = category_map.get(ftype, ftype.upper())
            loc = data.get("locate", [{}])[0]
            path = loc.get("file", "unknown")
            line = loc.get("line", 1)

            class_code = self._detect_class(ftype, data, loc) if category in ("SECRET", "SAST") else ""
            description, remediation = self._generate_description_remediation(category, class_code, data, loc)

            finding = {
                "category": category,
                "path": path,
                "severity": data.get("priority", "MEDIUM"),
                "description": description,
                "remediation": remediation,
            }

            if category in ("SECRET", "SAST"):
                finding["class"] = class_code
                finding["line"] = line
                finding["endLine"] = line

            if category == "SCA":
                finding["group"] = data.get("group", "unknown")
                finding["artifact"] = data.get("artifact", "unknown")
                finding["version"] = data.get("version", "unknown")
                advisory_ids = data.get("advisoryIds", [])
                finding["advisoryId"] = advisory_ids[0] if advisory_ids else "unknown"

            findings_array.append(finding)

        return {"findings": findings_array}

    def _generate_description_remediation(self, category: str, class_code: str,
                                          data: dict, loc: dict) -> tuple[str, str]:
        file_path = loc.get("file", "unknown")
        line = loc.get("line", "?")

        if category == "SECRET":
            class_name = SECRET_CLASSES.get(class_code, "секрет")
            return (
                f"Обнаружен {class_name.lower()} в файле {file_path} на строке {line}. Значение замаскировано.",
                "Вынести учётные данные в переменные окружения или использовать менеджер секретов."
            )

        elif category == "SCA":
            cve = data.get("advisoryIds", ["неизвестная уязвимость"])[0]
            artifact = data.get("artifact", "библиотека")
            version = data.get("version", "?")
            group = data.get("group", "")
            return (
                f"Библиотека {group}:{artifact} версии {version} содержит известную уязвимость {cve}.",
                f"Обновить зависимость {group}:{artifact} в build.gradle.kts до безопасной версии."
            )

        elif category == "SAST":
            class_name = SAST_CLASSES.get(class_code, "уязвимость")
            if class_code == "sql-injection":
                return (
                    f"SQL-инъекция через конкатенацию строк в файле {file_path} на строке {line}.",
                    "Использовать параметризованный запрос."
                )
            elif class_code == "tls-verification":
                return (
                    f"Ослабленная проверка TLS-сертификатов в файле {file_path} на строке {line}.",
                    "Удалить кастомный HostnameVerifier."
                )
            elif class_code == "credentialed-cors":
                return (
                    f"Излишне широкий CORS в файле {file_path} на строке {line}.",
                    "Указать конкретные доверенные домены."
                )
            elif class_code == "route-authorization":
                return (
                    f"Ошибка проверки доступа к маршруту в файле {file_path} на строке {line}.",
                    "Добавить .authenticated() в Spring Security."
                )
            elif class_code == "object-authorization":
                return (
                    f"Ошибка проверки доступа к объекту в файле {file_path} на строке {line}.",
                    "Добавить проверку прав доступа к объекту."
                )
            return (
                f"{class_name} в файле {file_path} на строке {line}.",
                "Применить стандартные практики безопасной разработки."
            )

        return (
            f"Обнаружена уязвимость в файле {file_path}.",
            "Требуется ручной анализ."
        )

    def _is_bad_response(self, text: str) -> bool:
        if text.count("🆔 ID:") == 0:
            return True
        if text.strip().startswith("{"):
            return True
        if re.search(r'^#+\s', text, re.MULTILINE):
            return True
        if re.search(r'\*\*[^*]+\*\*', text):
            return True
        english_words = len(re.findall(r'\b[a-zA-Z]{4,}\b', text))
        russian_words = len(re.findall(r'[а-яА-ЯёЁ]{4,}', text))
        if english_words > russian_words * 0.5 and russian_words < 10:
            return True
        return False

    def _build_prompt(self, all_findings: dict, grouped: dict[str, dict]) -> list:
        total = len(all_findings)
        type_stats = ", ".join(f"{t.upper()}: {len(items)}" for t, items in grouped.items())

        type_hints = {
            "secrets": "ПАРОЛИ/КЛЮЧИ/ТОКЕНЫ. НЕ показывай код секретов, пиши 'значение замаскировано'.",
            "sca": "УЯЗВИМЫЕ БИБЛИОТЕКИ с CVE. Укажи CVE из advisoryIds и версию.",
            "logic": "ОШИБКИ В КОДЕ: SQL-инъекции, TLS-обход, CORS, отсутствие авторизации."
        }

        hints_block = "\n".join(
            f"- {t.upper()}: {type_hints.get(t, 'стандартная уязвимость')}"
            for t in grouped.keys()
        )

        system_prompt = (
            f"Ты эксперт по ИБ.\n"
            f"Тебе прислали {total} находок: {type_stats}.\n"
            f"Сформируй ОДИН отчёт.\n\n"
            f"ПРАВИЛА:\n{hints_block}\n\n"
            f"СТРУКТУРА:\n"
            f"🔍 ИТОГОВЫЙ ОТЧЁТ\n"
            f"Всего: {total}\n\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🔍 КАТЕГОРИЯ: [ТИП] ([кол-во])\n\n"
            f"🔴 Приоритет: [priority]\n"
            f"🆔 ID: [id]\n"
            f"📁 Файл: [file] строка [line]\n"
            f"⚠️ Риск: [...]\n"
            f"💡 Исправление: [...]\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"ОБЩИЕ ПРАВИЛА:\n"
            f"- СТРОГО на русском\n"
            f"- ЗАПРЕЩЕНО: *, #, `, <>, Markdown\n"
            f"- Обработай ВСЕ {total} находок\n"
            f"- Упоминай ТОЛЬКО те файлы, которые есть во входных данных"
        )

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"JSON:\n{json.dumps(all_findings, ensure_ascii=False, indent=2)}"}
        ]

    async def _call_yandex(self, messages: list) -> str:
        url = "https://llm.api.cloud.yandex.net/foundationModels/v1/completion"
        headers = {
            "Authorization": f"Bearer {self.yandex_token}",
            "x-folder-id": self.yandex_folder_id,
            "Content-Type": "application/json"
        }
        payload = {
            "modelUri": f"gpt://{self.yandex_folder_id}/yandexgpt/latest",
            "completionOptions": {
                "stream": False,
                "temperature": 0.1,
                "maxTokens": "3000"
            },
            "messages": [
                {"role": m["role"], "text": m["content"]}
                for m in messages
            ]
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            return resp.json()["result"]["alternatives"][0]["message"]["text"]

    async def _call_ollama(self, messages: list) -> str:
        prompt_text = "\n".join(
            [f"{m['role'].upper()}:\n{m['content']}" for m in messages]
        )

        async with httpx.AsyncClient(timeout=180.0) as client:
            resp = await client.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.ollama_model,
                    "prompt": prompt_text,
                    "stream": False,
                    "temperature": 0.1,
                    "num_predict": 3000
                }
            )
            resp.raise_for_status()
            return resp.json()["response"]

    def _python_fallback_text(self, all_findings: dict, grouped: dict[str, dict]) -> str:
        lines = [f"🔍 ИТОГОВЫЙ ОТЧЁТ — Cyber Garden", f"Всего находок: {len(all_findings)}\n"]

        type_order = ["secrets", "sca", "logic"]
        ordered_types = [t for t in type_order if t in grouped] + \
                        [t for t in grouped.keys() if t not in type_order]

        for ftype in ordered_types:
            items = grouped[ftype]
            lines.append("━" * 30)
            lines.append(f"🔍 КАТЕГОРИЯ: {ftype.upper()} ({len(items)} находок)\n")

            for fid, data in items.items():
                loc = data.get("locate", [{}])[0]
                lines.append(f"🔴 Приоритет: {data.get('priority', 'MEDIUM')}")
                lines.append(f"🆔 ID: {fid}")
                lines.append(f"📁 Файл: {loc.get('file', 'unknown')} строка {loc.get('line', '?')}")

                class_code = self._detect_class(ftype, data, loc)
                description, remediation = self._generate_description_remediation(
                    ftype.upper(), class_code, data, loc
                )
                lines.append(f"⚠️ Риск: {description}")
                lines.append(f"💡 Исправление: {remediation}")
                lines.append("")

        return "\n".join(lines)

    def _validate(self, ai_text: str, all_findings: dict) -> str:
        real_files = {
            loc["file"]
            for data in all_findings.values()
            for loc in data.get("locate", [])
        }
        real_files.update({f.split("/")[-1] for f in real_files})

        mentioned = set(re.findall(r'[\w/\\\.]+\.(?:kts|kt|yml|yaml|properties)\b', ai_text))
        fake = {m for m in mentioned if m not in real_files and m.split("/")[-1] not in real_files}

        if fake:
            ai_text += f"\n\n⚠️ Системная проверка: ИИ упомянул файлы, которых нет в находках: {', '.join(fake)}."

        return ai_text