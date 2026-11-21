# core.py
"""
Ядро — обход репозитория, классификация файлов, валидация
Kotlin/Spring Boot + Gradle, структурный «парсинг» .kt и поэтапный
возврат прогресса. Передает управление в WorkflowEngine.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import AsyncIterator

from nodes.base import NodeContext
from workflow_engine import WorkflowEngine


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


async def process_repo(url: str, graph_json: dict, mode: str = "sync") -> AsyncIterator[ProgressEvent]:
    """
    Асинхронный генератор: отдаёт ProgressEvent по мере работы.
    mode: "sync" (для кнопки, стримим в SSE) или "async" (для расписания, просто собираем результаты).
    """
    from repo_fetch import fetch_repo

    yield ProgressEvent(Stage.CLONING, 5, f"Клонирую {url}")

    async with fetch_repo(url) as repo:
        yield ProgressEvent(
            Stage.WALKING, 15,
            f"Найдено файлов: {len(repo.files)}",
            {"run_id": repo.run_id, "mode": mode},
        )

        layout = _classify(repo.files, repo.root)
        layout.run_id = repo.run_id

        yield ProgressEvent(
            Stage.VALIDATING, 25,
            "Проверяю, что это Kotlin/Spring Boot + Gradle",
            {"counts": layout.counts(), "mode": mode},
        )

        if not layout.is_kotlin_spring_project:
            yield ProgressEvent(
                Stage.ERROR, 25,
                "Репозиторий не похож на Kotlin/Spring Boot + Gradle",
                {"counts": layout.counts(), "mode": mode},
            )
            return

        # Парсинг Kotlin
        total = len(layout.kotlin_files)
        parsed: list[dict] = []
        for i, kt in enumerate(layout.kotlin_files, start=1):
            parsed.append(await asyncio.to_thread(_parse_kotlin_file, kt, repo.root))
            percent = 25 + int(20 * i / total) if total else 45
            yield ProgressEvent(
                Stage.PARSING, percent,
                f"Парсинг Kotlin: {i}/{total}",
                {"file": kt.name, "mode": mode},
            )

        # Формируем контекст для нод
        context = NodeContext(
            files=repo.files,
            root=repo.root,
            run_id=repo.run_id
        )

        # Инициализируем движок графа
        db_path = Path(__file__).parent / "data" / "vulnerabilities.json"
        engine = WorkflowEngine(db_path=db_path)

        all_findings = []
        
        # Запускаем граф и транслируем его события
        async for event in engine.execute_graph(graph_json, context):
            if event["type"] == "node_start":
                yield ProgressEvent(
                    Stage.SCANNING, 50, 
                    f"Запуск ноды: {event['node_type']}",
                    {"node_id": event["node_id"], "mode": mode}
                )
            elif event["type"] == "node_result":
                if event["findings"]:
                    all_findings.extend(event["findings"])
                    yield ProgressEvent(
                        Stage.SCANNING, 60,
                        f"Нода {event['node_id']} нашла {len(event['findings'])} проблем",
                        {"node_id": event["node_id"], "mode": mode}
                    )
            elif event["type"] == "node_error":
                yield ProgressEvent(Stage.ERROR, 0, f"Ошибка: {event['message']}")
                return
            elif event["type"] == "workflow_done":
                yield ProgressEvent(
                    Stage.DONE, 100,
                    f"Анализ завершен. Найдено проблем: {len(all_findings)}",
                    {
                        "run_id": repo.run_id,
                        "counts": layout.counts(),
                        "parsed_kotlin": parsed,
                        "findings": all_findings,
                        "mode": mode
                    },
                )