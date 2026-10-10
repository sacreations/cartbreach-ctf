from __future__ import annotations

import os
import re
import secrets
import time
import urllib.parse
from contextlib import asynccontextmanager
from typing import Any

import bcrypt
import httpx
import psycopg
from fastapi import Cookie, Depends, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel


DATABASE_URL = os.getenv("DATABASE_URL")
SESSION_COOKIE = "cartbreach_session"
SESSION_MAX_AGE = 60 * 60 * 8
sessions: dict[str, tuple[dict[str, Any], float]] = {}
oauth_states: dict[str, float] = {}

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "http://portal.cartbreach.local/api/v1/auth/google/callback",
)


def init_db_schema() -> None:
    if not DATABASE_URL:
        return
    try:
        with psycopg.connect(DATABASE_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute("""
                    ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(32) DEFAULT 'approved';
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider VARCHAR(32) DEFAULT 'local';
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS google_sub VARCHAR(255) UNIQUE;
                    ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
                    UPDATE users SET status = 'approved' WHERE status IS NULL;
                    UPDATE users SET auth_provider = 'local' WHERE auth_provider IS NULL;
                """)
            connection.commit()
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db_schema()
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
            if cursor.description is None:
                connection.commit()
                return []
            columns = [column.name for column in cursor.description]
            rows = cursor.fetchall()
            connection.commit()
            return [dict(zip(columns, row)) for row in rows]


def public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user.get("email"),
        "role": user["role"],
        "status": user.get("status", "approved"),
        "auth_provider": user.get("auth_provider", "local"),
    }


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


def require_approved_user(user: dict[str, Any] = Depends(require_user)) -> dict[str, Any]:
    status = user.get("status", "approved")
    if status == "pending":
        raise HTTPException(status_code=403, detail="Account pending administrator approval")
    if status != "approved":
        raise HTTPException(status_code=403, detail="Account access denied")
    return user


def require_admin(user: dict[str, Any] = Depends(require_user)) -> dict[str, Any]:
    if user.get("status") != "approved" or user.get("role") != "admin":
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
        "SELECT id, username, password_hash, email, role, status, auth_provider FROM users WHERE username = %s",
        (payload.username,),
    )
    user = users[0] if users else None
    if not user or not user.get("password_hash") or not bcrypt.checkpw(payload.password.encode(), user["password_hash"].encode()):
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


@app.get("/api/v1/auth/google/login")
def google_login() -> RedirectResponse:
    if GOOGLE_CLIENT_ID:
        state = secrets.token_urlsafe(16)
        oauth_states[state] = time.time() + 600
        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "access_type": "online",
            "prompt": "select_account",
        }
        url = f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
        return RedirectResponse(url, status_code=302)
    return RedirectResponse("/api/v1/auth/google/callback?mock=true", status_code=302)


@app.get("/api/v1/auth/google/callback")
async def google_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    mock: str | None = None,
    mock_email: str | None = None,
) -> RedirectResponse:
    if error:
        return RedirectResponse(f"/?oauth_error={urllib.parse.quote(error)}", status_code=302)

    sub: str | None = None
    email: str | None = None
    name: str | None = None

    if mock == "true" or (not GOOGLE_CLIENT_ID and not code):
        email = mock_email or "google_user@cartbreach.local"
        sub = f"mock-google-{secrets.token_hex(4)}"
        name = email.split("@")[0]
    else:
        if not code:
            raise HTTPException(status_code=400, detail="Missing authorization code")
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_res = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uri": GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            )
            if token_res.status_code != 200:
                return RedirectResponse("/?oauth_error=token_exchange_failed", status_code=302)
            token_data = token_res.json()
            access_token = token_data.get("access_token")

            userinfo_res = await client.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if userinfo_res.status_code != 200:
                return RedirectResponse("/?oauth_error=userinfo_failed", status_code=302)
            userinfo = userinfo_res.json()
            sub = userinfo.get("sub")
            email = userinfo.get("email")
            name = userinfo.get("name") or (email.split("@")[0] if email else "google_user")

    if not sub or not email:
        return RedirectResponse("/?oauth_error=invalid_profile", status_code=302)

    users = query_database(
        "SELECT id, username, email, role, status, auth_provider, google_sub FROM users WHERE google_sub = %s OR email = %s",
        (sub, email),
    )
    if users:
        user = users[0]
        if not user.get("google_sub"):
            query_database(
                "UPDATE users SET google_sub = %s, auth_provider = 'google' WHERE id = %s",
                (sub, user["id"]),
            )
            user["google_sub"] = sub
            user["auth_provider"] = "google"
    else:
        base_username = re.sub(r"[^a-zA-Z0-9_-]", "", (name or "user").lower()) or "user"
        username = base_username
        counter = 1
        while query_database("SELECT 1 FROM users WHERE username = %s", (username,)):
            username = f"{base_username}_{counter}"
            counter += 1

        created = query_database(
            """
            INSERT INTO users (username, email, role, status, auth_provider, google_sub)
            VALUES (%s, %s, 'guest', 'pending', 'google', %s)
            RETURNING id, username, email, role, status, auth_provider, google_sub
            """,
            (username, email, sub),
        )
        user = created[0]

    session_id = secrets.token_urlsafe(32)
    safe_user = public_user(user)
    sessions[session_id] = (safe_user, time.time() + SESSION_MAX_AGE)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )
    return response


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
def list_challenges(_: dict[str, Any] = Depends(require_approved_user)) -> dict[str, list[dict[str, Any]]]:
    return {"challenges": STAGES}


@app.get("/api/v1/challenges/{stage_id}")
def get_challenge(stage_id: int, _: dict[str, Any] = Depends(require_approved_user)) -> dict[str, Any]:
    challenge = next((stage for stage in STAGES if stage["id"] == stage_id), None)
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return {"challenge": challenge}


@app.get("/api/v1/leaderboard")
def leaderboard(_: dict[str, Any] = Depends(require_approved_user)) -> dict[str, list[dict[str, Any]]]:
    return {"teams": []}


@app.get("/api/v1/admin/health")
def admin_health(_: dict[str, Any] = Depends(require_admin)) -> dict[str, str]:
    return health()


@app.get("/api/v1/admin/users")
def list_admin_users(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    users = query_database(
        "SELECT id, username, email, role, status, auth_provider, created_at FROM users ORDER BY id ASC"
    )
    clean_users = [
        {
            "id": u["id"],
            "username": u["username"],
            "email": u.get("email"),
            "role": u["role"],
            "status": u.get("status", "approved"),
            "auth_provider": u.get("auth_provider", "local"),
            "created_at": u["created_at"].isoformat() if u.get("created_at") else None,
        }
        for u in users
    ]
    return {"users": clean_users}


@app.post("/api/v1/admin/users/{user_id}/approve")
def approve_user(user_id: int, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    updated = query_database(
        "UPDATE users SET status = 'approved' WHERE id = %s RETURNING id, username, role, status",
        (user_id,),
    )
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")
    user = updated[0]
    for sid, (sess_user, exp) in list(sessions.items()):
        if sess_user.get("id") == user_id:
            sess_user["status"] = "approved"
            sessions[sid] = (sess_user, exp)
    return {"status": "ok", "user": user}


@app.post("/api/v1/admin/users/{user_id}/reject")
def reject_user(user_id: int, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    updated = query_database(
        "UPDATE users SET status = 'rejected' WHERE id = %s RETURNING id, username, role, status",
        (user_id,),
    )
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")
    user = updated[0]
    for sid, (sess_user, exp) in list(sessions.items()):
        if sess_user.get("id") == user_id:
            sess_user["status"] = "rejected"
            sessions[sid] = (sess_user, exp)
    return {"status": "ok", "user": user}

