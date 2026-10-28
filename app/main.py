"""
StrikeNet Pentest Orchestrator — FastAPI бэкенд.

REST:
  GET/POST /api/runs
  GET      /api/runs/{id}
  POST     /api/runs/{id}/pause | /stop
  GET      /api/runs/{id}/findings
  GET      /api/findings          ?severity=&tool=&run_id=
  GET      /api/findings/export   ?format=sarif|json|csv&run_id=
  GET      /api/stats
  GET/POST /api/schedule
  DELETE   /api/schedule/{id}
  GET      /api/tools/status
  POST     /api/tools/{name}/check
  GET/PUT  /api/settings
  POST     /api/settings/llm/test
  GET/POST /api/settings/llm
  DELETE   /api/settings/llm/{id}

WebSocket:
  /ws/runs        — broadcast статусов (каждые 2 сек)
  /ws/logs/{run_id} — поток строк лога

Фронтенд (orchestrator-panel.html) отдаётся на GET /.
"""
import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.responses import HTMLResponse, Response, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import db
from .models import RunCreate, ScheduleCreate, LLMProviderCreate, SettingsUpdate, LLMTestRequest, LLMActiveConfig
from .llm_config import get_provider_info, PRESETS, build_env_for_tool
from .pipeline import run_pipeline
from .reports import generate_sarif, generate_json, generate_csv
from .scheduler import init_scheduler, register_schedule, unregister_schedule, scheduler
from .ws_manager import ws_manager

# путь к HTML-панели (лежит рядом с директорией app/)
PANEL_HTML = Path(__file__).parent.parent / "panel" / "orchestrator-panel.html"
STATIC_DIR = Path(__file__).parent / "static"

# хранилище задач asyncio для возможности отмены (pause/stop)
_pipeline_tasks: dict[int, asyncio.Task] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    init_scheduler()
    # фоновая рассылка статусов активных прогонов каждые 2 сек
    task = asyncio.create_task(_broadcast_run_statuses())
    yield
    task.cancel()
    scheduler.shutdown(wait=False)


app = FastAPI(title="StrikeNet Orchestrator", version="0.9.1", lifespan=lifespan)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ── ФРОНТЕНД ──
@app.get("/", response_class=HTMLResponse)
async def serve_panel():
    if PANEL_HTML.exists():
        return HTMLResponse(PANEL_HTML.read_text())
    return HTMLResponse("<h1>Panel not found.</h1><p>Put orchestrator-panel.html in panel/</p>")


# ── STATS ──
@app.get("/api/stats")
async def get_stats():
    return db.get_run_stats()


# ── RUNS ──
@app.get("/api/runs")
async def list_runs(status: str | None = None, limit: int = 50):
    return db.list_runs(status=status, limit=limit)


@app.post("/api/runs", status_code=201)
async def create_run(body: RunCreate):
    run_id = db.create_run(
        target_url=body.target_url,
        target_repo=body.target_repo,
        tools=body.tools,
        llm_provider=body.llm_provider,
        llm_model=body.llm_model,
        nono_enabled=body.nono_enabled,
        reset_stages=body.reset_between_stages,
    )
    task = asyncio.create_task(
        run_pipeline(
            run_id=run_id,
            target_url=body.target_url,
            target_repo=body.target_repo or "",
            tools=body.tools,
            nono_enabled=body.nono_enabled,
            reset_between=body.reset_between_stages,
            llm_provider=body.llm_provider,
        )
    )
    _pipeline_tasks[run_id] = task
    task.add_done_callback(lambda _: _pipeline_tasks.pop(run_id, None))
    return {"run_id": run_id, "status": "pending"}


@app.get("/api/runs/{run_id}")
async def get_run(run_id: int):
    run = db.get_run(run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    run["stages"] = db.get_stages(run_id)
    return run


@app.post("/api/runs/{run_id}/pause")
async def pause_run(run_id: int):
    task = _pipeline_tasks.get(run_id)
    if task and not task.done():
        task.cancel()
        db.update_run(run_id, status="paused")
        return {"status": "paused"}
    raise HTTPException(400, "Run not found or already finished")


@app.post("/api/runs/{run_id}/stop")
async def stop_run(run_id: int):
    task = _pipeline_tasks.get(run_id)
    if task and not task.done():
        task.cancel()
    db.update_run(run_id, status="failed")
    return {"status": "stopped"}


@app.get("/api/runs/{run_id}/findings")
async def run_findings(run_id: int):
    return db.get_findings(run_id=run_id)


# ── FINDINGS ──
@app.get("/api/findings")
async def get_findings(
    run_id: int | None = None,
    severity: str | None = None,
    tool: str | None = None,
):
    return db.get_findings(run_id=run_id, severity=severity, tool=tool)


@app.get("/api/findings/export")
async def export_findings(
    run_id: int = Query(...),
    format: str = Query("sarif", regex="^(sarif|json|csv)$"),
):
    if format == "sarif":
        return Response(
            content=generate_sarif(run_id),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=run-{run_id}.sarif"},
        )
    if format == "json":
        return Response(
            content=generate_json(run_id),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=run-{run_id}.json"},
        )
    # csv
    return Response(
        content=generate_csv(run_id),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=run-{run_id}.csv"},
    )


# ── SCHEDULE ──
@app.get("/api/schedule")
async def list_schedules():
    return db.list_schedules()


@app.post("/api/schedule", status_code=201)
async def create_schedule(body: ScheduleCreate):
    sched_id = db.create_schedule(
        target_url=body.target_url,
        target_repo=body.target_repo,
        tools=body.tools,
        cron=body.cron,
        active=body.active,
    )
    sched = {"id": sched_id, "target_url": body.target_url,
             "target_repo": body.target_repo, "tools": body.tools,
             "cron": body.cron, "active": body.active}
    if body.active:
        register_schedule(sched)
    return sched


@app.delete("/api/schedule/{sched_id}")
async def delete_schedule(sched_id: int):
    unregister_schedule(sched_id)
    db.delete_schedule(sched_id)
    return {"deleted": sched_id}


# ── TOOLS ──
TOOL_CHECK_CMDS = {
    "deepaudit": ["docker", "images", "-q", "deepaudit:latest"],
    "hexstrike": ["docker", "exec", "hexstrike", "curl", "-s",
                  "http://localhost:8888/health"],
    "strix":     ["docker", "exec", "strix-cli", "strix", "--version"],
    "shannon":   ["npx", "@keygraph/shannon@latest", "--version"],
}


@app.get("/api/tools/status")
async def tools_status():
    results = []
    for name, cmd in TOOL_CHECK_CMDS.items():
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            _, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            online = proc.returncode == 0
        except Exception:
            online = False
        results.append({"name": name, "status": "online" if online else "offline"})
    return results


@app.post("/api/tools/{name}/check")
async def check_tool(name: str):
    cmd = TOOL_CHECK_CMDS.get(name)
    if not cmd:
        raise HTTPException(404, "Unknown tool")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=8)
        ok = proc.returncode == 0
        return {"name": name, "status": "online" if ok else "offline",
                "output": stdout.decode(errors="replace")[:200]}
    except Exception as e:
        return {"name": name, "status": "offline", "error": str(e)}


# ── SETTINGS ──
@app.get("/api/settings")
async def get_settings():
    return db.get_settings()


@app.put("/api/settings")
async def save_settings(body: SettingsUpdate):
    data = {k: v for k, v in body.model_dump().items() if v is not None}
    db.save_settings(data)
    return db.get_settings()


@app.get("/api/settings/llm")
async def list_llm():
    providers = db.list_llm_providers()
    # маскируем ключи
    for p in providers:
        if p.get("api_key"):
            p["api_key"] = p["api_key"][:8] + "***"
    return providers


@app.post("/api/settings/llm", status_code=201)
async def add_llm(body: LLMProviderCreate):
    pid = db.add_llm_provider(
        name=body.name,
        provider_type=body.provider_type,
        endpoint=body.endpoint,
        api_key=body.api_key,
        default_model=body.default_model,
    )
    return {"id": pid}


@app.delete("/api/settings/llm/{pid}")
async def delete_llm(pid: int):
    db.delete_llm_provider(pid)
    return {"deleted": pid}


# ── АКТИВНЫЙ LLM-ПРОВАЙДЕР (централизованный) ──
@app.get("/api/llm")
async def get_llm_config():
    """Возвращает текущий активный LLM-конфиг с замаскированным ключом."""
    return get_provider_info()


@app.put("/api/llm")
async def set_llm_config(body: LLMActiveConfig):
    """Сохраняет активный LLM-провайдер для всего оркестратора."""
    db.save_settings({
        "llm_provider_type": body.provider_type,
        "llm_api_key":       body.api_key or "",
        "llm_model":         body.model or "",
        "llm_custom_url":    body.custom_url or "",
    })
    return get_provider_info()


@app.get("/api/llm/presets")
async def get_llm_presets():
    """Список доступных пресетов провайдеров с бесплатными моделями."""
    return {
        name: {
            "base_url":    p["base_url"],
            "free_models": p.get("free_models", []),
            "default_model": p.get("default_model", ""),
        }
        for name, p in PRESETS.items()
    }


@app.post("/api/llm/test")
async def test_active_llm():
    """Проверяет текущий активный LLM-провайдер минимальным запросом."""
    from .llm_config import get_active_provider
    provider = get_active_provider()
    if not provider:
        return {"status": "error", "detail": "LLM-провайдер не настроен"}
    if not provider["api_key"] and provider["provider_type"] != "ollama":
        return {"status": "error", "detail": "API-ключ не задан"}

    headers = {"Content-Type": "application/json",
               "Authorization": f"Bearer {provider['api_key']}"}
    if provider["provider_type"] == "openrouter":
        headers["HTTP-Referer"] = "https://github.com/your/strikenet"

    payload = {
        "model": provider["model"],
        "messages": [{"role": "user", "content": "Reply with the word PONG only."}],
        "max_tokens": 8,
    }
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                provider["base_url"].rstrip("/") + "/chat/completions",
                headers=headers, json=payload,
            )
        if r.status_code < 400:
            data = r.json()
            reply = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            return {
                "status": "ok",
                "http_status": r.status_code,
                "model_reply": reply,
                "model": provider["model"],
                "endpoint": provider["base_url"],
            }
        return {"status": "error", "http_status": r.status_code,
                "detail": r.text[:300]}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


@app.get("/api/llm/env/{tool}")
async def get_tool_env_preview(tool: str):
    """
    Показывает, какие env-переменные получит конкретный инструмент.
    Ключ замаскирован. Полезно для отладки конфигурации.
    """
    from .llm_config import get_active_provider
    provider = get_active_provider()
    env = build_env_for_tool(tool, provider)
    # маскируем ключи
    safe = {}
    key_vars = {"OPENAI_API_KEY", "LLM_API_KEY", "OPENROUTER_API_KEY",
                "KEYGRAPH_API_KEY", "DEEPAUDIT_API_KEY", "OPENCODE_API_KEY",
                "DOCKER_LLM_KEY"}
    for k, v in env.items():
        safe[k] = (v[:8] + "***") if k in key_vars and v else v
    return {"tool": tool, "env": safe}


@app.post("/api/settings/llm/test")
async def test_llm(body: LLMTestRequest):
    """Отправляет минимальный запрос к LLM-провайдеру и проверяет ответ."""
    headers = {"Content-Type": "application/json"}
    if body.api_key:
        headers["Authorization"] = f"Bearer {body.api_key}"
    payload = {
        "model": body.model or "gpt-4o-mini",
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 5,
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                body.endpoint.rstrip("/") + "/chat/completions",
                headers=headers, json=payload,
            )
        if r.status_code < 400:
            return {"status": "ok", "http_status": r.status_code}
        return {"status": "error", "http_status": r.status_code,
                "detail": r.text[:200]}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# ── WEBSOCKET: RUNS ──
@app.websocket("/ws/runs")
async def ws_runs(ws: WebSocket):
    await ws_manager.connect_runs(ws)
    try:
        while True:
            await asyncio.sleep(30)  # держим соединение живым
    except WebSocketDisconnect:
        ws_manager.disconnect_runs(ws)


# ── WEBSOCKET: LOGS ──
@app.websocket("/ws/logs/{run_id}")
async def ws_logs(ws: WebSocket, run_id: int):
    await ws_manager.connect_logs(ws, run_id)
    try:
        while True:
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        ws_manager.disconnect_logs(ws, run_id)


# ── BACKGROUND: BROADCAST RUN STATUSES ──
async def _broadcast_run_statuses():
    """Каждые 2 секунды рассылает статусы активных прогонов всем WS-клиентам."""
    while True:
        try:
            runs = db.list_runs(status="running", limit=20)
            if runs:
                await ws_manager.broadcast_runs({
                    "type": "runs_status",
                    "runs": [
                        {"id": r["id"], "status": r["status"],
                         "progress": r["progress"], "target": r["target_url"]}
                        for r in runs
                    ],
                })
        except Exception:
            pass
        await asyncio.sleep(2)
