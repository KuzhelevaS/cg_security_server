import re
from pathlib import Path
from .base import BaseNode, NodeContext, Finding

class SecretsNode(BaseNode):
    def __init__(self):
        self.patterns = [
            {"rule_id": "SEC001", "name": "AWS Access Key", "pattern": r"(?i)(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "severity": "CRITICAL"},
            {"rule_id": "SEC002", "name": "Приватный ключ", "pattern": r"-----BEGIN (RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----", "severity": "CRITICAL"},
            {"rule_id": "SEC003", "name": "JWT Token", "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "severity": "HIGH"},
            {"rule_id": "SEC004", "name": "Пароль в коде", "pattern": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]+['\"]", "severity": "HIGH"},
            {"rule_id": "SEC005", "name": "API Ключ", "pattern": r"(?i)(api_key|apikey|secret_key|access_token)\s*[:=]\s*['\"][a-zA-Z0-9_-]{16,}['\"]", "severity": "HIGH"},
            {"rule_id": "SEC006", "name": "Токен Telegram", "pattern": r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}", "severity": "CRITICAL"}
        ]

    @property
    def node_type(self) -> str:
        return "secrets_scanner"

    @property
    def display_name(self) -> str:
        return "Поиск секретов (Passwords, Keys)"

    def run(self, context: NodeContext) -> list[Finding]:
        findings = []
        for file in context.files:
            if file.suffix.lower() not in {".kt", ".kts", ".yml", ".yaml", ".sql"}:
                continue
            try:
                text = file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            
            for rule in self.patterns:
                regex = re.compile(rule["pattern"])
                for match in regex.finditer(text):
                    line_number = text.count("\n", 0, match.start()) + 1
                    
                    try:
                        # Берем путь относительно корня репозитория. 
                        # Обрезка имени папки репозитория происходит позже, в core.py
                        rel_path = file.relative_to(context.root).as_posix()
                    except ValueError:
                        rel_path = str(file)
                    
                    findings.append(Finding(
                        type="SECRET",
                        line=line_number,
                        file=rel_path,
                        severity=rule["severity"]
                    ))
        return findings