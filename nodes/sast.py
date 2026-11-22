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
                "pattern": r'(?i)jdbc\.\w+\s*\([^)]*\$[^)]*\)',
                "severity": "CRITICAL",
            },
            {
                "ext": {".kt"},
                "rule_id": "SAST002",
                "name": "Небезопасная настройка CORS",
                "pattern": r'(?i)(allowedOrigins?|allowedOriginPatterns?)\s*=\s*(?:listOf\(\s*\)|\[\s*\]|\s*"\*"\s*)',
                "severity": "HIGH",
            },
            {
                "ext": {".kt"},
                "rule_id": "SAST003",
                "name": "Использование небезопасного Random",
                "pattern": r'\b(Random|Math\.random)\s*\(',
                "severity": "MEDIUM",
            },
            {
                "ext": {".kt"},
                "rule_id": "SAST004",
                "name": "Отключение проверки SSL/TLS сертификата",
                "pattern": r'HostnameVerifier\s*\{\s*[^}]*->\s*true\s*\}|X509TrustManager|checkServerTrusted\s*\{',
                "severity": "HIGH",
            },
            {
                "ext": {".kt"},
                "rule_id": "SAST005",
                "name": "Внедрение выражений (Expression Injection)",
                "pattern": r'(?i)StringSubstitutor\.createInterpolator\(\)|SpelExpressionParser|ScriptEngineManager',
                "severity": "CRITICAL",
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
            applicable_rules = [r for r in self.rules if ext in r["ext"]]
            if not applicable_rules:
                continue
            try:
                lines = file.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            
            for line_num, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith("--") or stripped.startswith("//") or stripped.startswith("*"):
                    continue
                for rule in applicable_rules:
                    if re.search(rule["pattern"], line):
                        try:
                            rel_path = file.relative_to(context.root).as_posix()
                        except ValueError:
                            rel_path = str(file)
                        
                        findings.append(Finding(
                            type="SAST",
                            line=line_num,
                            file=rel_path,
                            severity=rule["severity"]
                        ))
        return findings