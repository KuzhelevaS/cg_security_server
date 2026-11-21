# nodes/sast.py
import re
from pathlib import Path
from .base import BaseNode, NodeContext, Finding

class SastNode(BaseNode):
    def __init__(self):
        self.rules = [ 
            {
                "ext": {".kt"},
                "rule_id": "SAST001",
                "name": "Возможная SQL-инъекция",
                # Ищем вызовы jdbc.query... или execute... 
                # где внутри строки (") есть символ $ и фигурная скобка {
                "pattern": r'(?i)jdbc\.\w+\s*\(\s*"[^"]*\$[^"]*"',
                "severity": "CRITICAL",
                "message": "В SQL-запрос подставляется переменная (интерполяция). Используйте параметризованные запросы (замените '${...}' на '?')."
            },
            {
                "ext": {".kt"},
                "rule_id": "SAST002",
                "name": "Небезопасная настройка CORS",
                # Ищем allowedOrigins, allowedOriginPatterns и т.д.
                # Разрешаем синтаксис: = "*", = listOf("*"), ("*")
                "pattern": r'(?i)(allowedOrigins?|allowedOriginPatterns?)\s*(?:=\s*(?:listOf\(\s*)?|\()\s*["\']\*["\']',
                "severity": "HIGH",
                "message": "Разрешен CORS для всех источников (*). Ограничьте список доверенными доменами (особенно если allowCredentials = true)."
            },
            {
                "ext": {".kt"},
                "rule_id": "SAST003",
                "name": "Использование небезопасного Random",
                "pattern": r'\b(Random|Math\.random)\s*\(',
                "severity": "MEDIUM",
                "message": "Использование небезопасного генератора случайных чисел. Используйте SecureRandom."
            },
            {
                "ext": {".kt"},
                "rule_id": "SAST004",
                "name": "Отключение проверки SSL/TLS сертификата",
                # Ищем HostnameVerifier, который всегда возвращает true, 
                # или TrustManager, который принимает все сертификаты
                "pattern": r'HostnameVerifier\s*\{\s*_\s*,\s*_\s*->\s*true\s*\}|X509TrustManager|checkServerTrusted\s*\{\s*_\s*,\s*_\s*->',
                "severity": "HIGH",
                "message": "Отключена проверка SSL-сертификата (HostnameVerifier или TrustManager). Это делает приложение уязвимым к MITM-атакам."
            },
                        {
                "ext": {".kt"},
                "rule_id": "SAST005",
                "name": "Внедрение выражений (Expression Injection)",
                # Ищем использование StringSubstitutor.createInterpolator или SpEL-парсеров
                "pattern": r'(?i)StringSubstitutor\.createInterpolator\(\)|SpelExpressionParser|ScriptEngineManager',
                "severity": "CRITICAL",
                "message": "Использование интерпретатора выражений с внешними данными может привести к выполнению произвольного кода (RCE)."
            },
        ]

    @property
    def node_type(self) -> str:
        return "sast_scanner"

    @property
    def display_name(self) -> str:
        return "Логический анализ (SAST)"

    def run(self, context: NodeContext) -> list[Finding]:
        findings = []
        
        for file in context.files:
            ext = file.suffix.lower()
            # Проверяем, есть ли правила для этого расширения
            applicable_rules = [r for r in self.rules if ext in r["ext"]]
            if not applicable_rules:
                continue

            try:
                lines = file.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue

            for line_num, line in enumerate(lines, start=1):
                # Пропускаем комментарии для SQL и Kotlin
                stripped = line.strip()
                if stripped.startswith("--") or stripped.startswith("//") or stripped.startswith("*"):
                    continue

                for rule in applicable_rules:
                    if re.search(rule["pattern"], line):
                        try:
                            rel_path = file.relative_to(context.root).as_posix()
                        except ValueError:
                            rel_path = str(file)

                        snippet = stripped
                        if len(snippet) > 100:
                            snippet = snippet[:97] + "..."

                        findings.append(Finding(
                            rule_id=rule["rule_id"],
                            name=rule["name"],
                            severity=rule["severity"],
                            file=rel_path,
                            line=line_num,
                            snippet=snippet,
                            raw_data=rule["message"]
                        ))
        return findings