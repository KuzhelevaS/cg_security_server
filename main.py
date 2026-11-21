# main.py
import asyncio
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from workflow_session import WorkflowSession
from core import process_repo


SESSIONS: dict[str, WorkflowSession] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    # На всякий случай: если что-то осталось — чистим
    from repo_fetch import cleanup_repo
    for session in SESSIONS.values():
        if session.repo_path:
            cleanup_repo(session.repo_path)
    SESSIONS.clear()


app = FastAPI(title="AI Security Workflow", lifespan=lifespan)


class ScanRequest(BaseModel):
    workflow: list[dict]


@app.post("/api/scan/start")
async def start_scan(request: ScanRequest):
    session_id = str(uuid.uuid4())
    session = WorkflowSession(session_id=session_id)
    SESSIONS[session_id] = session

    repo_url = None
    for node in request.workflow:
        if node.get("type") == "projecttype":
            repo_url = node.get("info", {}).get("data")
            break

    if not repo_url:
        SESSIONS.pop(session_id, None)
        raise HTTPException(400, "В графе нет ноды projecttype с URL репозитория")

    # Запускаем фон; НЕ await — иначе запрос повиснет
    asyncio.create_task(run_workflow_background(repo_url, request.workflow, session))

    return {"status": "Ok", "session_id": session_id, "text": "Сканирование запущено"}


@app.get("/api/scan/status")
async def get_status(session_id: str):
    session = SESSIONS.get(session_id)
    if session is None:
        raise HTTPException(404, "Сессия не найдена")

    base = {
        "session_id": session_id,
        "stage": session.stage,
        "progress": session.progress,
        "text": session.current_text,
        "findings_count": len(session.findings),
    }

    if session.status == "error":
        return {"status": "Error", "text": session.error_text or "Ошибка", **base}

    if session.status == "ended":
        return {
            "status": "End",
            "text": session.current_text,
            "data": session.final_data,
            **base,
        }

    # running
    # Промежуточные данные не отдаём — фронт дождётся End.
    # (Если хочется отдавать "по мере поступления" — можно вернуть
    #  {"findings": session.findings}, но тогда фронт должен уметь merge.)
    return {"status": "Ok", "text": session.current_text, **base}


async def run_workflow_background(
    repo_url: str,
    graph_json: list[dict],
    session: WorkflowSession,
):
    try:
        # process_repo — асинхронный генератор, поэтому async for
        async for _event in process_repo(repo_url, graph_json, session):
            # session обновляется внутри process_repo / engine,
            # здесь только «прокачиваем» генератор
            pass
    except Exception as e:
        session.status = "error"
        session.error_text = f"Критическая ошибка: {e}"
        session.stage = "error"
        session.progress = 0
        session.current_text = session.error_text
    finally:
        # fetch_repo уже почистил папку; на всякий случай
        session.repo_path = None


@app.get("/api/scan/cleanup")
async def cleanup_session(session_id: str):
    """Опционально: удалить сессию вручную (например, после скачивания отчёта)."""
    SESSIONS.pop(session_id, None)
    return {"status": "Ok"}