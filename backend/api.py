"""Web API. Streams the agent's steps to the browser as Server-Sent Events.

Run:  uvicorn backend.api:app --reload --port 8000
If frontend/dist exists (after `npm run build`), it is served at / so one process serves everything.

Endpoints
  GET  /api/health                  mode (claude | scripted) and tenants
  GET  /api/suggestions?tenant=     most exposed CVEs (quick-start chips)
  GET  /api/decisions?tenant=       decision history for one tenant, with supersede links
  POST /api/chat                    {message, tenant, session_id} -> text/event-stream of agent events
"""
import asyncio
import json
import os
import queue
import re
import threading
import time
from collections import OrderedDict, defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend import config
from backend.agent.graphview import subgraph_from_output
from backend.agent.loop import run_agent
from backend.agent.scripted import run_scripted
from backend.agent.tools import Toolbox
from backend.graph.client import get_graph

TENANTS = [t.strip() for t in os.getenv("TENANTS", "acme,globex").split(",") if t.strip()]
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "30"))        # chat requests per client per window
RATE_WINDOW = int(os.getenv("RATE_WINDOW", "600"))     # seconds
MAX_SESSIONS = 200
DIST = config.ROOT / "frontend" / "dist"


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    tenant: str = config.DEFAULT_TENANT
    session_id: str = Field(default="default", max_length=64, pattern=r"^[A-Za-z0-9_-]+$")


def llm_enabled() -> bool:
    return bool(os.getenv("ANTHROPIC_API_KEY")) and os.getenv("DEMO_MODE", "").lower() not in ("1", "true")


def friendly_error(e: Exception) -> str:
    name = type(e).__name__
    if name == "AuthenticationError":
        return "The Anthropic API key was rejected. Check ANTHROPIC_API_KEY."
    if name == "RateLimitError":
        return "The Anthropic API rate limit was hit. Wait a moment and retry."
    if name in ("NotFoundError", "BadRequestError"):
        return f"The model request was rejected ({e}). Check ANTHROPIC_MODEL."
    return f"{name}: {e}"


def create_app(graph=None) -> FastAPI:
    app = FastAPI(title="Supply-chain triage agent")
    origins = [o for o in os.getenv("CORS_ORIGINS", "").split(",") if o]
    if origins:
        app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["*"], allow_headers=["*"])

    sessions: OrderedDict[str, list] = OrderedDict()
    hits: dict[str, deque] = defaultdict(deque)
    lock = threading.Lock()

    def box_for(tenant: str) -> Toolbox:
        if tenant not in TENANTS:
            raise HTTPException(400, f"Unknown tenant '{tenant}'. Allowed: {', '.join(TENANTS)}")
        return Toolbox(graph=graph if graph is not None else get_graph(), tenant=tenant)

    def rate_limited(client: str) -> bool:
        now = time.time()
        with lock:
            dq = hits[client]
            while dq and now - dq[0] > RATE_WINDOW:
                dq.popleft()
            if len(dq) >= RATE_LIMIT:
                return True
            dq.append(now)
            return False

    @app.get("/api/health")
    def health():
        return {"ok": True, "mode": "claude" if llm_enabled() else "scripted", "tenants": TENANTS,
                "model": config.ANTHROPIC_MODEL if llm_enabled() else None}

    @app.get("/api/suggestions")
    def suggestions(tenant: str = config.DEFAULT_TENANT):
        return box_for(tenant).most_exposed_cves(5)

    @app.get("/api/decisions")
    def decisions(tenant: str = config.DEFAULT_TENANT):
        return {"tenant": tenant, "decisions": box_for(tenant).list_decisions(50)}

    @app.post("/api/chat")
    async def chat(req: ChatRequest, request: Request):
        box = box_for(req.tenant)
        client_id = request.client.host if request.client else "unknown"
        if rate_limited(client_id):
            return JSONResponse({"error": f"Rate limit: {RATE_LIMIT} requests per {RATE_WINDOW // 60} minutes."}, status_code=429)

        use_llm = llm_enabled()
        key = f"{req.tenant}:{req.session_id}"
        events: queue.Queue = queue.Queue()

        def on_event(e: dict):
            if e["type"] == "tool_result":
                g = subgraph_from_output(e["tool"], e["output"])
                if g:
                    e = {**e, "graph": g}
            events.put(e)

        def work():
            try:
                events.put({"type": "meta", "mode": "claude" if use_llm else "scripted", "tenant": req.tenant})
                if use_llm:
                    with lock:
                        history = list(sessions.get(key, []))
                    res = run_agent(req.message, history=history, on_event=on_event, toolbox=box)
                    with lock:
                        sessions[key] = res.messages
                        sessions.move_to_end(key)
                        while len(sessions) > MAX_SESSIONS:
                            sessions.popitem(last=False)
                else:
                    run_scripted(req.message, box, on_event)
            except Exception as e:  # surface any failure to the browser instead of a dead stream
                events.put({"type": "error", "message": friendly_error(e)})
            finally:
                events.put(None)

        threading.Thread(target=work, daemon=True).start()

        async def stream():
            loop = asyncio.get_running_loop()
            while True:
                item = await loop.run_in_executor(None, events.get)
                if item is None:
                    break
                yield f"data: {json.dumps(item, default=str)}\n\n"

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    if DIST.exists():  # serve the built React app (must be registered last so /api wins)
        app.mount("/", StaticFiles(directory=DIST, html=True), name="web")
    return app


app = create_app()
