# core.py
import asyncio
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Union

from nodes.base import NodeContext
from workflow_engine import WorkflowEngine
from workflow_session import WorkflowSession
from repo_fetch import clone_repo_only, extract_zip_only

class Stage(str, Enum):
    CLONING    = "cloning"
    WALKING    = "walking"
    VALIDATING = "validating"
    PARSING    = "parsing"
    SCANNING   = "scanning"
    DONE       = "done"
    ERROR      = "error"

@dataclass
class ProjectLayout:
    run_id: str
    root: Path
    kotlin_files: list[Path] = field(default_factory=list)
    gradle_build_files: list[Path] = field(default_factory=list)
    gradle_settings_files: list[Path] = field(default_factory=list)
    config_files: list[Path] = field(default_factory=list)
    sql_files: list[Path] = field(default_factory=list)
    other_files: list[Path] = field(default_factory=list)

    @property
    def is_kotlin_spring_project(self) -> bool:
        return bool(self.kotlin_files) and bool(self.gradle_build_files)

def _classify(files: list[Path], root: Path) -> ProjectLayout:
    layout = ProjectLayout(run_id="", root=root)
    for p in files:
        name = p.name.lower()
        suffix = p.suffix.lower()
        if suffix == ".kt":
            layout.kotlin_files.append(p)
        elif name == "build.gradle.kts":
            layout.gradle_build_files.append(p)
        elif name == "settings.gradle.kts":
            layout.gradle_settings_files.append(p)
        elif suffix in {".yml", ".yaml"}:
            layout.config_files.append(p)
        elif suffix == ".sql":
            layout.sql_files.append(p)
        else:
            layout.other_files.append(p)
    return layout

def _parse_kotlin_file(path: Path, root: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return {"path": str(path), "error": "unreadable"}
    try:
        rel_path = path.relative_to(root).as_posix()
    except ValueError:
        rel_path = str(path)
    return {
        "path": str(rel_path),
        "lines": len(text.splitlines()),
        "has_sql": any(k in text.lower() for k in ("select ", "insert ", "update ", "delete ")),
    }

async def process_repo(source: Union[str, Path], graph_json: list[dict], session: WorkflowSession, source_type: str = "git"):
    """
    Основной процесс: клонирование/распаковка, парсинг, запуск движка.
    source_type: "git" (строка URL) или "zip" (путь к файлу).
    """
    session.status = "running"
    
    # --- 1. КЛОНИРОВАНИЕ ИЛИ РАСПАКОВКА ---
    if source_type == "git":
        session.current_text = "Клонирование репозитория..."
        try:
            run_id, repo_root, files = await asyncio.to_thread(clone_repo_only, str(source))
            session.repo_path = repo_root
        except Exception as e:
            session.status = "error"
            session.error_text = f"Ошибка клонирования: {e}"
            return
    elif source_type == "zip":
        session.current_text = "Распаковка архива..."
        try:
            # source здесь - это Path к загруженному zip-файлу
            run_id, repo_root, files = await asyncio.to_thread(extract_zip_only, source)
            session.repo_path = repo_root
        except Exception as e:
            session.status = "error"
            session.error_text = f"Ошибка распаковки: {e}"
            return
    else:
        session.status = "error"
        session.error_text = "Неизвестный тип источника (ожидается git или zip)"
        return

    session.current_text = f"Найдено файлов: {len(files)}"

    # --- 2. КЛАССИФИКАЦИЯ И ВАЛИДАЦИЯ ---
    layout = _classify(files, repo_root)
    if not layout.is_kotlin_spring_project:
        session.status = "error"
        session.error_text = "Репозиторий не похож на Kotlin/Spring Boot + Gradle"
        return

    # --- 3. ПАРСИНГ KOTLIN ---
    session.current_text = "Парсинг Kotlin-файлов..."
    for kt in layout.kotlin_files:
        await asyncio.to_thread(_parse_kotlin_file, kt, repo_root)

    # --- 4. ЗАПУСК ПРОВЕРОК (ДВИЖОК) ---
    session.current_text = "Запуск проверок безопасности..."
    try:
        context = NodeContext(files=files, root=repo_root, run_id=run_id)
        db_path = Path(__file__).parent / "data" / "vulnerabilities.json"
        engine = WorkflowEngine(db_path=db_path)
        
        # Движок обновляет session.final_data и session.status = "ended"
        await engine.execute_graph(graph_json, context, session)
        
    except Exception as e:
        session.status = "error"
        session.error_text = f"Ошибка выполнения проверок: {e}"