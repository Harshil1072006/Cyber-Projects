"""
FastAPI application — main entry point.
All routes are registered here from the api/ submodules.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database import init_db
from backend.api.scans import router as scans_router
from backend.api.tools import router as tools_router
from backend.api.ws import router as ws_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="VAPT Command Center",
    description="A local-first intelligence platform for automated penetration testing.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans_router, prefix="/api/scans", tags=["Scans"])
app.include_router(tools_router, prefix="/api/tools", tags=["Tools"])
app.include_router(ws_router, prefix="/ws", tags=["WebSocket"])


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "VAPT Command Center"}
