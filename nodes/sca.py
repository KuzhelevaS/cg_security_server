import re
import json
from pathlib import Path
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
        if not self.db_path.exists():
            return []
        with open(self.db_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("vulnerabilities", [])

    def _parse_version(self, v: str) -> tuple:
        v = v.strip().strip("'\"")
        parts = v.split(".")
        result = []
        for p in parts:
            match = re.match(r"^(\d+)", p)
            if match:
                result.append(int(match.group(1)))
            else:
                result.append(0)
        return tuple(result)

    def _is_vulnerable(self, version: str, ranges: list[dict]) -> bool:
        v_tuple = self._parse_version(version)
        for r in ranges:
            lower = r.get("lower")
            upper = r.get("upper")
            lower_inc = r.get("lowerInclusive", False)
            upper_inc = r.get("upperInclusive", False)
            
            if lower is not None:
                low_tuple = self._parse_version(lower)
                if lower_inc:
                    if v_tuple < low_tuple: continue
                else:
                    if v_tuple <= low_tuple: continue
                    
            if upper is not None:
                up_tuple = self._parse_version(upper)
                if upper_inc:
                    if v_tuple > up_tuple: continue
                else:
                    if v_tuple >= up_tuple: continue
                    
            return True
        return False

    def _extract_deps_from_line(self, line: str) -> list[tuple[str, str, str]]:
        deps = []
        pattern_str = re.compile(r'["\']([a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+):([^"\']+)["\']')
        for match in pattern_str.finditer(line):
            group, artifact, version = match.group(1), match.group(2), match.group(3)
            if "$" not in version:
                deps.append((group, artifact, version))
        
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
                                
                                findings.append(Finding(
                                    type="SCA",
                                    line=line_num,
                                    file=rel_path,
                                    severity=vuln["severity"]
                                ))
        return findings