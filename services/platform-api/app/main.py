from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any

import psycopg
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://cart_user:cart_db_pass_2026!@postgres-data:5432/cartbreach",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="CartBreach Platform API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


STAGES = [
    {"id": 1, "slug": "recon-01", "title": "Exposed Staging Repository", "points": 100, "status": "available"},
    {"id": 2, "slug": "access-02", "title": "Broken Object Authorization", "points": 150, "status": "locked"},
    {"id": 3, "slug": "trust-03", "title": "Forged Payment Signature", "points": 200, "status": "locked"},
    {"id": 4, "slug": "harvest-04", "title": "Database Snapshot Recovery", "points": 250, "status": "locked"},
    {"id": 5, "slug": "exec-05", "title": "Inventory Export Injection", "points": 300, "status": "locked"},
    {"id": 6, "slug": "escape-06", "title": "Scheduled Task Escalation", "points": 350, "status": "locked"},
]


def query_database(query: str) -> list[dict[str, Any]]:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(query)
            columns = [column.name for column in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]


@app.get("/health")
def health() -> dict[str, str]:
    try:
        query_database("SELECT 1 AS ready")
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    return {"status": "ok"}


@app.get("/api/v1/challenges")
def list_challenges() -> dict[str, list[dict[str, Any]]]:
    return {"challenges": STAGES}


@app.get("/api/v1/challenges/{stage_id}")
def get_challenge(stage_id: int) -> dict[str, Any]:
    challenge = next((stage for stage in STAGES if stage["id"] == stage_id), None)
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return {"challenge": challenge}


@app.get("/api/v1/leaderboard")
def leaderboard() -> dict[str, list[dict[str, Any]]]:
    return {"teams": []}
