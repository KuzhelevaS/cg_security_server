# main.py
import asyncio
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from workflow_session import WorkflowSession
from core import process_repo
from repo_fetch import cleanup_repo

# Глобальное хранилище сессий
SESSIONS: dict[str, WorkflowSession] = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Здесь можно добавить периодическую очистку старых сессий
    yield
    # При выключении удаляем все оставшиеся репозитории
    for session in SESSIONS.values():
        if session.repo_path:
            cleanup_repo(session.repo_path)

app = FastAPI(title="AI Security Workflow", lifespan=lifespan)

class ScanRequest(BaseModel):
    workflow: list[dict]

@app.post("/api/scan/start")
async def start_scan(request: ScanRequest):
    """1. Эндпоинт для запуска (фронт получает session_id)."""
    session_id = str(uuid.uuid4())
    session = WorkflowSession(session_id=session_id)
    SESSIONS[session_id] = session

    # Ищем URL в графе
    repo_url = None
    for node in request.workflow:
        if node.get("type") == "projecttype":
            repo_url = node.get("info", {}).get("data")
            break

    if not repo_url:
        raise HTTPException(400, "В графе нет ноды projecttype с URL репозитория")

    # Запускаем в фоне
    asyncio.create_task(run_workflow_background(repo_url, request.workflow, session))
    
    return {"status": "Ok", "session_id": session_id, "text": "Сканирование запущено"}

@app.get("/api/scan/status")
async def get_status(session_id: str):
    if session_id not in SESSIONS:
        raise HTTPException(404, "Сессия не найдена")
    
    session = SESSIONS[session_id]

    if session.status == "error":
        return {"status": "Error", "text": session.error_text}
    
    # Если данные готовы (мы дошли до message)
    if session.data_ready and session.final_data:
        data_to_return = session.final_data
        
        # Если это последняя нода и процесс завершен — возвращаем End
        if session.status == "ended":
            session.data_ready = False # Сбрасываем флаг
            return {
                "status": "End",
                "text": session.current_text,
                "data": data_to_return
            }
        else:
            # Если процесс еще идет (например, после message есть другие ветки)
            # Отдаем данные с Ok. Флаг НЕ сбрасываем, чтобы фронт мог получить их снова, 
            # если запросит статус еще раз.
            return {
                "status": "Ok",
                "text": session.current_text,
                "data": data_to_return
            }
        
    if session.status == "ended":
        # Если процесс завершен, но message не было
        return {"status": "End", "text": "Завершено (отчет без отправки сообщения)"}

    # Процесс еще идет, данных пока нет
    return {"status": "Ok", "text": session.current_text}

async def run_workflow_background(repo_url: str, graph_json: list[dict], session: WorkflowSession):
    """Фоновая задача с гарантированной очисткой."""
    try:
        await process_repo(repo_url, graph_json, session)
    except Exception as e:
        session.status = "error"
        session.error_text = f"Критическая ошибка: {e}"
    finally:
        # Удаляем папку репозитория после завершения
        if session.repo_path:
            print(f"[Session {session.session_id}] Удаляю {session.repo_path}")
            cleanup_repo(session.repo_path)
            session.repo_path = None

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)