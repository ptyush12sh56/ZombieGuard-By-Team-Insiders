"""
ZombieGuard — FastAPI Main Application
Tech stack (exact match to Technical Approach slide):
  Backend  : Python 3.11 + FastAPI + Pydantic validation
  ML/AI    : Scikit-learn (IsolationForest) + NumPy + LSTM sim
  Parsing  : BeautifulSoup (HTML/XML API docs)
  Database : SQL Alchemy (SQLite) — api_endpoints, risk_scores, audit_log, etc.
  Streaming: Apache Kafka (in-process broker for POC)
  Infra    : Uvicorn ASGI server
"""
import pathlib
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from .db.session import init_db
from .core.kafka_bus import start_kafka, stop_kafka
from .api.routes.api import router as api_router

BASE   = pathlib.Path(__file__).parent.parent
TMPL   = BASE / "templates"
STATIC = BASE / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup
    init_db()
    start_kafka()
    print("✅ ZombieGuard — DB initialised · Kafka broker started")
    yield
    # shutdown
    stop_kafka()
    print("ZombieGuard shutting down")


app = FastAPI(
    title="ZombieGuard API",
    description=(
        "**Zombie API Discovery & Defence System — iDEA 2.0 Hackathon PS9**\n\n"
        "**Pipeline:** BeautifulSoup → Apache Kafka → IsolationForest+LSTM "
        "→ NumPy CVSS → SQL Alchemy → FastAPI Auto-Defence\n\n"
        "**Tech Stack:** Python 3.11 · FastAPI · scikit-learn · NumPy · "
        "BeautifulSoup · Pydantic · SQL Alchemy · Kafka\n\n"
        "**Team:** Insiders · **PS9** · Union Bank of India"
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

if STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/", include_in_schema=False)
def serve_frontend():
    idx = TMPL / "index.html"
    return FileResponse(str(idx)) if idx.exists() else JSONResponse(
        {"message": "ZombieGuard API — visit /docs", "version": "1.0.0"})


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok", "service": "ZombieGuard", "version": "1.0.0",
            "stack": "FastAPI+sklearn+NumPy+BeautifulSoup+SQLAlchemy+Kafka"}
