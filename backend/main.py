from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router
from backend_addon.domain_intelligence import router as intelligence_router


app = FastAPI(
    title="PhishingLens API",
    description="AI-powered URL phishing detection and contextual security analysis.",
    version="1.0.0"
)

# Allow the GitHub Pages frontend to communicate with this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://puttimonish.github.io",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.include_router(intelligence_router)

BASE_DIR = Path(__file__).resolve().parents[1]

FRONTEND_DIR = BASE_DIR / "frontend"

INDEX_FILE = FRONTEND_DIR / "index.html"

# Static CSS and JavaScript
app.mount(
    "/app",
    StaticFiles(
        directory=str(FRONTEND_DIR),
        html=True
    ),
    name="frontend"
)

# Main website
@app.get("/", include_in_schema=False)
def website():
    return FileResponse(INDEX_FILE)

# API root information
@app.get("/api", include_in_schema=False)
def api_root():
    return {
        "application": "PhishingLens",
        "version": "1.0.0",
        "status": "running",
        "documentation": "/docs"
    }