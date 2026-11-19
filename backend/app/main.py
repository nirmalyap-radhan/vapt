import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import auth, scan, history, lab_scan
from app.core.config import settings
from app.db.database import engine
from app.db import models

models.Base.metadata.create_all(bind=engine)
os.makedirs("reports", exist_ok=True)

app = FastAPI(
    title=settings.APP_NAME,
    description="Full-stack AI-powered Web VAPT platform — recon, scanning, lab testing, and reporting.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_ORIGIN, "http://localhost:3000", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix=settings.API_PREFIX + "/auth", tags=["Auth"])
app.include_router(scan.router, prefix=settings.API_PREFIX + "/scan", tags=["Scan"])
app.include_router(lab_scan.router, prefix=settings.API_PREFIX + "/scan", tags=["Lab Scan"])
app.include_router(history.router, prefix=settings.API_PREFIX + "/history", tags=["History"])


@app.get("/")
def root():
    return {"message": "VAPTProX API v2.0", "status": "operational", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok", "app": settings.APP_NAME}
