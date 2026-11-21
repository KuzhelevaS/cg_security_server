# workflow_session.py
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

@dataclass
class WorkflowSession:
    session_id: str
    status: str = "running"      # running, error, ended
    current_text: str = "Инициализация..."
    error_text: str | None = None
    final_data: dict | None = None
    data_ready: bool = False      # Флаг, что мы дошли до ноды message
    repo_path: Path | None = None # Путь к склонированному репо (для очистки)