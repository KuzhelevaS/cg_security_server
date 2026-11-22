# main.py
import asyncio
import json
import tempfile
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from pydantic import BaseModel

from workflow_session import WorkflowSession
from core import process_repo
from repo_fetch import cleanup_repo

# Глобальное хранилище сессий (в памяти)
SESSIONS: dict[str, WorkflowSession] = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Управление жизненным циклом (очистка при выключении)."""
    yield
    # При выключении сервера удаляем все оставшиеся папки репозиториев
    for session in SESSIONS.values():
        if session.repo_path:
            cleanup_repo(session.repo_path)
            session.repo_path = None

app = FastAPI(title="AI Security Workflow", lifespan=lifespan)

# ==========================================
# 1. ЗАПУСК СКАНИРОВАНИЯ (GIT)
# ==========================================
class GitScanRequest(BaseModel):
    workflow: list[dict]

@app.post("/api/scan/start/git")
async def start_scan_git(request: GitScanRequest):
    """Эндпоинт для запуска по ссылке на GitHub."""
    graph_json = request.workflow
    
    # Ищем URL в графе
    repo_url = None
    for node in graph_json:
        if node.get("type") == "projecttype":
            repo_url = node.get("info", {}).get("data")
            break
            
    if not repo_url:
        raise HTTPException(400, "В графе нет URL репозитория (нода projecttype)")

    session_id = str(uuid.uuid4())
    session = WorkflowSession(session_id=session_id)
    SESSIONS[session_id] = session

    # Запускаем в фоне
    asyncio.create_task(run_workflow_background(repo_url, "git", graph_json, session))
    
    return {"status": "Ok", "session_id": session_id, "text": "Клонирование и сканирование запущены"}


# ==========================================
# 2. ЗАПУСК СКАНИРОВАНИЯ (ZIP)
# ==========================================
@app.post("/api/scan/start/upload")
async def start_scan_upload(
    file: UploadFile = File(..., description="ZIP архив с проектом"),
    workflow_json: str = Form(..., description="JSON графа в виде строки")
):
    """Эндпоинт для загрузки ZIP-архива."""
    # 1. Проверяем расширение файла
    if not file.filename.lower().endswith(".zip"):
        raise HTTPException(400, "Поддерживаются только ZIP архивы")

    # 2. Парсим JSON графа
    try:
        graph_json = json.loads(workflow_json)
    except json.JSONDecodeError:
        raise HTTPException(400, "Некорректный JSON графа")

    # 3. Сохраняем архив во временную папку
    temp_dir = Path(tempfile.gettempdir())
    temp_zip_path = temp_dir / f"upload_{uuid.uuid4().hex}.zip"
    
    try:
        with open(temp_zip_path, "wb") as buffer:
            while chunk := await file.read(1024 * 1024):  # по 1 МБ
                buffer.write(chunk)
    except Exception as e:
        raise HTTPException(500, f"Ошибка сохранения файла: {e}")

    # 4. Создаем сессию и запускаем в фоне
    session_id = str(uuid.uuid4())
    session = WorkflowSession(session_id=session_id)
    SESSIONS[session_id] = session

    asyncio.create_task(run_workflow_background(temp_zip_path, "zip", graph_json, session))
    
    return {"status": "Ok", "session_id": session_id, "text": "Распаковка и сканирование запущены"}


# ==========================================
# 3. ОПРОС СТАТУСА (ПОЛЛИНГ)
# ==========================================
@app.get("/api/scan/status")
async def get_status(session_id: str):
    """Эндпоинт для поллинга статуса выполнения."""
    if session_id not in SESSIONS:
        raise HTTPException(404, "Сессия не найдена")
    
    session = SESSIONS[session_id]

    if session.status == "error":
        return {"status": "Error", "text": session.error_text}
    
    if session.status == "ended":
        # Возвращаем итоговый JSON только в самом конце
        return {
            "status": "End",
            "text": session.current_text,
            "data": session.final_data
        }

    # Процесс еще идет
    return {"status": "Ok", "text": session.current_text}


# ==========================================
# 4. ФОНОВАЯ ЗАДАЧА С ОЧИСТКОЙ
# ==========================================
async def run_workflow_background(source_data, source_type: str, graph_json: list[dict], session: WorkflowSession):
    """Фоновая задача с гарантированной очисткой временных файлов."""
    try:
        await process_repo(source_data, graph_json, session, source_type=source_type)
    except Exception as e:
        session.status = "error"
        session.error_text = f"Критическая ошибка: {e}"
    finally:
        # 1. Удаляем папку с распакованным/склонированным репо
        if session.repo_path:
            print(f"[Session {session.session_id}] Удаляю папку: {session.repo_path}")
            cleanup_repo(session.repo_path)
            session.repo_path = None
            
        # 2. Если был загружен zip-архив, удаляем и его
        if source_type == "zip" and isinstance(source_data, Path):
            if source_data.exists():
                print(f"[Session {session.session_id}] Удаляю архив: {source_data}")
                source_data.unlink()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)