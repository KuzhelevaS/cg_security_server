# nodes/sca.py
import re
import json
from pathlib import Path
from typing import Any
from .base import BaseNode, NodeContext, Finding

class ScaNode(BaseNode):
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._vulnerabilities = self._load_db()

    @property
    def node_type(self) -> str:
        return "sca_scanner"

    @property
    def display_name(self) -> str:
        return "Проверка зависимостей (SCA)"

    def _load_db(self) -> list[dict]:
        """Загружаем базу уязвимостей из JSON."""
        if not self.db_path.exists():
            return []
        with open(self.db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("vulnerabilities", [])

    def _parse_version(self, v: str) -> tuple:
        """
        Превращает строку версии в кортеж чисел для сравнения.
        '1.9' -> (1, 9, 0)
        '20230618' -> (20230618,)
        """
        # Убираем возможные кавычки и пробелы
        v = v.strip().strip("'\"")
        parts = v.split(".")
        # Заменяем нечисловые части на 0 (на случай, если версия типа 1.0.0-RC1)
        # Но в нашем снимке только numeric-dot-separated
        result = []
        for p in parts:
            # Извлекаем только цифры в начале компонента (на всякий случай)
            match = re.match(r"^(\d+)", p)
            if match:
                result.append(int(match.group(1)))
            else:
                result.append(0)
        return tuple(result)

    def _is_vulnerable(self, version: str, ranges: list[dict]) -> bool:
        """Проверяет, попадает ли версия в один из уязвимых диапазонов."""
        v_tuple = self._parse_version(version)
        
        for r in ranges:
            lower = r.get("lower")
            upper = r.get("upper")
            lower_inc = r.get("lowerInclusive", False)
            upper_inc = r.get("upperInclusive", False)

            # Проверка нижней границы
            if lower is not None:
                low_tuple = self._parse_version(lower)
                if lower_inc:
                    if v_tuple < low_tuple: continue
                else:
                    if v_tuple <= low_tuple: continue
            
            # Проверка верхней границы
            if upper is not None:
                up_tuple = self._parse_version(upper)
                if upper_inc:
                    if v_tuple > up_tuple: continue
                else:
                    if v_tuple >= up_tuple: continue
            
            # Если прошли обе проверки — версия уязвима
            return True
            
        return False

    def _extract_deps_from_line(self, line: str) -> list[tuple[str, str, str]]:
        """Ищет зависимости в одной строке файла."""
        deps = []
        # Паттерн 1: "group:artifact:version"
        pattern_str = re.compile(r'["\']([a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+):([^"\']+)["\']')
        for match in pattern_str.finditer(line):
            group, artifact, version = match.group(1), match.group(2), match.group(3)
            if "$" not in version:
                deps.append((group, artifact, version))
                
        # Паттерн 2: "group:artifact" version "version"
        pattern_version = re.compile(r'["\']([a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+)["\']\s+version\s+["\']([^"\']+)["\']')
        for match in pattern_version.finditer(line):
            group, artifact, version = match.group(1), match.group(2), match.group(3)
            if "$" not in version:
                deps.append((group, artifact, version))
                
        return deps

    def run(self, context: NodeContext) -> list[Finding]:
        findings = []
        
        for file in context.files:
            if file.name != "build.gradle.kts":
                continue

            try:
                # Читаем файл построчно, чтобы знать номера строк
                lines = file.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
                
            for line_num, line in enumerate(lines, start=1):
                deps = self._extract_deps_from_line(line)
                
                for group, artifact, version in deps:
                    for vuln in self._vulnerabilities:
                        if vuln["group"] == group and vuln["artifact"] == artifact:
                            if self._is_vulnerable(version, vuln.get("ranges", [])):
                                try:
                                    rel_path = file.relative_to(context.root).as_posix()
                                except ValueError:
                                    rel_path = str(file)
                                    
                                advisory_id = vuln.get("aliases", [vuln["id"]])[0] if vuln.get("aliases") else vuln["id"]
                                
                                findings.append(Finding(
                                    rule_id=advisory_id,
                                    name=f"Уязвимая зависимость: {group}:{artifact} (v{version})",
                                    severity=vuln["severity"],
                                    file=rel_path,
                                    line=line_num,  # <-- ТЕПЕРЬ ЗДЕСЬ РЕАЛЬНЫЙ НОМЕР СТРОКИ
                                    snippet=line.strip(), # <-- Показываем саму строку из Gradle
                                    raw_data=json.dumps(vuln, ensure_ascii=False)
                                ))
        return findings