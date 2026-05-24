"""
SentinelAI Python FastAPI Service
AI Agent, Log Parsing, Threat Detection, Enrichment
"""
import asyncio
import structlog
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from config.settings import settings
from config.database import connect_mongo, disconnect_mongo

# Routers
from modules.log_parser import router as parser_router
from modules.threat_detection import router as detection_router
from enrichment.enrichment import router as enrichment_router
from agents.gemini_agent import router as agent_router
from agents.autonomous_agent import router as autonomous_router

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle"""
    log.info("sentinelai_python_service_starting", port=settings.PORT)
    await connect_mongo()
    log.info("sentinelai_ready")
    yield
    log.info("sentinelai_shutting_down")
    await disconnect_mongo()


app = FastAPI(
    title="SentinelAI Python Agent",
    description="AI-powered threat detection, log parsing, and autonomous response",
    version="1.0.0",
    lifespan=lifespan,
)

# ─── Middleware ────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.NODE_SERVICE_URL, "http://localhost:3001"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    log.info("request", method=request.method, path=request.url.path)
    response = await call_next(request)
    log.info("response", status=response.status_code, path=request.url.path)
    return response


# ─── Exception Handlers ────────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.error("unhandled_exception", error=str(exc), path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)},
    )


# ─── Routers ──────────────────────────────────────────────────────────────────
app.include_router(parser_router, prefix="", tags=["Log Parsing"])
app.include_router(detection_router, prefix="", tags=["Threat Detection"])
app.include_router(enrichment_router, prefix="", tags=["Enrichment"])
app.include_router(agent_router, prefix="/agent", tags=["AI Agent"])
app.include_router(autonomous_router, prefix="/agent", tags=["Autonomous Response"])


# ─── Health ────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok", "service": "sentinelai-python", "version": "1.0.0"}


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.PORT,
        reload=settings.DEBUG,
        workers=settings.WORKERS,
        log_level="info",
    )
