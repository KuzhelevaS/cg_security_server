# repo_fetch.py
"""
Шаг 1: клонирование GitHub-репозитория в изолированную папку
с гарантированной очисткой и ограничением параллелизма.
"""
import asyncio
import hashlib
import os
import re
import shutil
import subprocess
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
import tempfile

#BASE_TMP = Path("/var/tmp/ai_security_workflow")
BASE_TMP = Path(tempfile.gettempdir()) / "ai_security_workflow"
ALLOWED_EXTS = {".yml", ".yaml", ".sql", ".kt", ".kts"}
SKIP_DIRS = {".git", "build", ".gradle", "out", "node_modules", ".idea"}

_CLONE_SEMAPHORE = asyncio.Semaphore(4)

# только https://github.com/<owner>/<repo> — блокирует file://, ssh://, --upload-pack=...
_GITHUB_RE = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+/?$")


@dataclass
class FetchedRepo:
    run_id: str
    root: Path
    files: list[Path]           # только отфильтрованные по ALLOWED_EXTS
    clone_url: str


def _validate_url(url: str) -> None:
    if not _GITHUB_RE.match(url):
        raise ValueError(f"Unsupported repo URL: {url!r}")


def _make_run_dir(url: str) -> tuple[str, Path]:
    run_id = uuid.uuid4().hex
    short_hash = hashlib.sha256(url.encode()).hexdigest()[:8]
    path = BASE_TMP / f"{short_hash}_{run_id}"
    path.mkdir(parents=True, exist_ok=False)
    return run_id, path


def _walk_filtered(root: Path) -> list[Path]:
    result: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in ALLOWED_EXTS:
                result.append(p)
    return result


def _clone_sync(url: str, dest: Path, timeout_s: int) -> None:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    cmd = [
        "git", "clone",
        "--depth", "1",
        "--single-branch",
        "--no-tags",
        url, str(dest),
    ]
    subprocess.run(
        cmd, check=True, timeout=timeout_s, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )


@asynccontextmanager
async def fetch_repo(url: str, *, timeout_s: int = 120):
    """
    Асинхронный контекст-менеджер: клонирует репо во временную папку,
    отдаёт FetchedRepo, гарантированно удаляет папку при выходе.
    """
    _validate_url(url)
    async with _CLONE_SEMAPHORE:
        run_id, run_dir = _make_run_dir(url)
        try:
            await asyncio.to_thread(_clone_sync, url, run_dir, timeout_s)
            files = _walk_filtered(run_dir)
            yield FetchedRepo(run_id=run_id, root=run_dir, files=files, clone_url=url)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

def clone_repo_only(url: str, timeout_s: int = 120) -> tuple[str, Path, list[Path]]:
    _validate_url(url)
    run_id, run_dir = _make_run_dir(url)
    _clone_sync(url, run_dir, timeout_s)
    files = _walk_filtered(run_dir)
    return run_id, run_dir, files

def cleanup_repo(run_dir: Path):
    import shutil
    shutil.rmtree(run_dir, ignore_errors=True)