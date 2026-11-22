# workflow_session.py
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

@dataclass
class WorkflowSession:
    session_id: str
    status: str = "running"       # running | error | ended
    current_text: str = "Инициализация..."
    error_text: str | None = None
    final_data: dict | None = None
    data_ready: bool = False
    repo_path: Path | None = None

    # Новое: аккумулятор находок, чтобы отдавать промежуточные данные
    # и не терять их при повторном опросе
    findings: list[dict] = field(default_factory=list)
    progress: int = 0             # 0..100 для UI
    stage: str = "init"          # cloning/walking/.../done/error