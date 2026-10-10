from __future__ import annotations

import os
import secrets
import time
from contextlib import asynccontextmanager
from typing import Any

import bcrypt
import psycopg
from fastapi import Cookie, Depends, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


DATABASE_URL = os.getenv("DATABASE_URL")
SESSION_COOKIE = "cartbreach_session"
SESSION_MAX_AGE = 60 * 60 * 8
sessions: dict[str, tuple[dict[str, Any], float]] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="CartBreach Platform API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5174"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    allow_credentials=True,
)


STAGES = [
    {"id": 1, "slug": "recon-01", "title": "Exposed Staging Repository", "points": 100, "status": "available"},
    {"id": 2, "slug": "access-02", "title": "Broken Object Authorization", "points": 150, "status": "locked"},
    {"id": 3, "slug": "trust-03", "title": "Forged Payment Signature", "points": 200, "status": "locked"},
    {"id": 4, "slug": "harvest-04", "title": "Database Snapshot Recovery", "points": 250, "status": "locked"},
    {"id": 5, "slug": "exec-05", "title": "Inventory Export Injection", "points": 300, "status": "locked"},
    {"id": 6, "slug": "escape-06", "title": "Scheduled Task Escalation", "points": 350, "status": "locked"},
]


class LoginRequest(BaseModel):
    username: str
    password: str


def query_database(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(query, params)
            columns = [column.name for column in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


def current_user(session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE)) -> dict[str, Any] | None:
    if not session_id:
        return None
    session = sessions.get(session_id)
    if not session:
        return None
    user, expires = session
    if expires <= time.time():
        sessions.pop(session_id, None)
        return None
    return user


def require_user(user: dict[str, Any] | None = Depends(current_user)) -> dict[str, Any]:
    if user is None:
        raise HTTPException(status_code=401, detail="Unauthenticated")
    return user


def require_admin(user: dict[str, Any] = Depends(require_user)) -> dict[str, Any]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@app.get("/health")
def health() -> dict[str, str]:
    try:
        query_database("SELECT 1 AS ready")
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc
    return {"status": "ok"}


@app.post("/api/v1/auth/login")
def login(payload: LoginRequest, response: Response) -> dict[str, Any]:
    users = query_database(
        "SELECT id, username, password_hash, role FROM users WHERE username = %s",
        (payload.username,),
    )
    user = users[0] if users else None
    if not user or not bcrypt.checkpw(payload.password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    session_id = secrets.token_urlsafe(32)
    safe_user = public_user(user)
    sessions[session_id] = (safe_user, time.time() + SESSION_MAX_AGE)
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )
    return {"user": safe_user}


@app.get("/api/v1/auth/me")
def me(user: dict[str, Any] = Depends(require_user)) -> dict[str, Any]:
    return {"user": user}


@app.post("/api/v1/auth/logout")
def logout(response: Response, session_id: str | None = Cookie(default=None, alias=SESSION_COOKIE)) -> dict[str, str]:
    if session_id:
        sessions.pop(session_id, None)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"status": "ok"}


@app.get("/api/v1/challenges")
def list_challenges(_: dict[str, Any] = Depends(require_user)) -> dict[str, list[dict[str, Any]]]:
    return {"challenges": STAGES}


@app.get("/api/v1/challenges/{stage_id}")
def get_challenge(stage_id: int, _: dict[str, Any] = Depends(require_user)) -> dict[str, Any]:
    challenge = next((stage for stage in STAGES if stage["id"] == stage_id), None)
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return {"challenge": challenge}


@app.get("/api/v1/leaderboard")
def leaderboard(_: dict[str, Any] = Depends(require_user)) -> dict[str, list[dict[str, Any]]]:
    return {"teams": []}


@app.get("/api/v1/admin/health")
def admin_health(_: dict[str, Any] = Depends(require_admin)) -> dict[str, str]:
    return health()
