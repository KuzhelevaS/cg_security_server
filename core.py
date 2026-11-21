# core.py
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import AsyncIterator

from nodes.base import NodeContext
from workflow_engine import WorkflowEngine
from workflow_session import WorkflowSession


class Stage(str, Enum):
    CLONING    = "cloning"
    WALKING    = "walking"
    VALIDATING = "validating"
    PARSING    = "parsing"
    SCANNING   = "scanning"
    DONE       = "done"
    ERROR      = "error"


@dataclass
class ProgressEvent:
    stage: Stage
    percent: int
    message: str
    payload: dict = field(default_factory=dict)


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

    def counts(self) -> dict[str, int]:
        return {
            "kotlin":          len(self.kotlin_files),
            "gradle_build":    len(self.gradle_build_files),
            "gradle_settings": len(self.gradle_settings_files),
            "config":          len(self.config_files),
            "sql":             len(self.sql_files),
            "other":           len(self.other_files),
        }


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
    lines = text.splitlines()
    return {
        "path": str(rel_path),
        "lines": len(lines),
        "bytes": len(text.encode("utf-8", errors="ignore")),
        "is_controller": "@RestController" in text or "@Controller" in text,
        "is_service":    "@Service" in text,
        "has_sql":       any(k in text.lower() for k in ("select ", "insert ", "update ", "delete ")),
    }


def _apply(session: WorkflowSession, stage: Stage, percent: int, message: str) -> None:
    """Единая точка обновления session — чтобы /status всегда видел актуальное."""
    session.stage = stage.value
    session.progress = percent
    session.current_text = message


async def process_repo(
    url: str,
    graph_json: list[dict],
    session: WorkflowSession,
) -> AsyncIterator[ProgressEvent]:
    """
    Асинхронный генератор: обновляет `session` по мере работы и отдаёт события.
    Вызывающий код может как стримить события, так и просто пройтись по ним.
    """
    from repo_fetch import fetch_repo

    _apply(session, Stage.CLONING, 5, f"Клонирую {url}")
    yield ProgressEvent(Stage.CLONING, 5, session.current_text)

    try:
        async with fetch_repo(url) as repo:
            session.repo_path = repo.root  # на случай падения до finally

            _apply(session, Stage.WALKING, 15, f"Найдено файлов: {len(repo.files)}")
            yield ProgressEvent(Stage.WALKING, 15, session.current_text,
                                {"run_id": repo.run_id, "files": len(repo.files)})

            layout = _classify(repo.files, repo.root)
            layout.run_id = repo.run_id

            _apply(session, Stage.VALIDATING, 25, "Проверяю, что это Kotlin/Spring Boot + Gradle")
            yield ProgressEvent(Stage.VALIDATING, 25, session.current_text,
                                {"counts": layout.counts()})

            if not layout.is_kotlin_spring_project:
                session.status = "error"
                session.error_text = "Репозиторий не похож на Kotlin/Spring Boot + Gradle"
                _apply(session, Stage.ERROR, 25, session.error_text)
                yield ProgressEvent(Stage.ERROR, 25, session.error_text,
                                    {"counts": layout.counts()})
                return

            # Парсинг Kotlin
            total = len(layout.kotlin_files)
            parsed: list[dict] = []
            for i, kt in enumerate(layout.kotlin_files, start=1):
                parsed.append(await asyncio.to_thread(_parse_kotlin_file, kt, repo.root))
                percent = 25 + int(20 * i / total) if total else 45
                msg = f"Парсинг Kotlin: {i}/{total}"
                _apply(session, Stage.PARSING, percent, msg)
                yield ProgressEvent(Stage.PARSING, percent, msg, {"file": kt.name})

            context = NodeContext(files=repo.files, root=repo.root, run_id=repo.run_id)

            db_path = Path(__file__).parent / "data" / "vulnerabilities.json"
            engine = WorkflowEngine(db_path=db_path)

            # Запускаем граф — события транслируем наружу и обновляем session
            async for event in engine.execute_graph(graph_json, context, session):
                if event["type"] == "node_start":
                    msg = f"Запуск ноды: {event['node_type']}"
                    _apply(session, Stage.SCANNING, 50, msg)
                    yield ProgressEvent(Stage.SCANNING, 50, msg,
                                        {"node_id": event["node_id"]})

                elif event["type"] == "node_result":
                    if event.get("findings"):
                        msg = (f"Нода {event['node_id']} нашла "
                               f"{len(event['findings'])} проблем "
                               f"(всего {len(session.findings)})")
                    else:
                        msg = f"Нода {event['node_id']} завершена без находок"
                    _apply(session, Stage.SCANNING, 60, msg)
                    yield ProgressEvent(Stage.SCANNING, 60, msg,
                                        {"node_id": event["node_id"]})

                elif event["type"] == "node_error":
                    session.status = "error"
                    session.error_text = f"Ошибка: {event['message']}"
                    _apply(session, Stage.ERROR, 0, session.error_text)
                    yield ProgressEvent(Stage.ERROR, 0, session.error_text)
                    return

                elif event["type"] == "workflow_done":
                    # WorkflowEngine уже положил final_data и выставил status=ended
                    msg = f"Анализ завершен. Найдено проблем: {len(session.findings)}"
                    _apply(session, Stage.DONE, 100, msg)
                    yield ProgressEvent(Stage.DONE, 100, msg, {
                        "run_id": repo.run_id,
                        "counts": layout.counts(),
                        "parsed_kotlin": parsed,
                        "findings": session.findings,
                    })

    finally:
        # fetch_repo чистит папку сам; здесь только обнуляем ссылку
        session.repo_path = None