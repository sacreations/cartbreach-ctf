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

                    CREATE TABLE IF NOT EXISTS challenge_solves (
                        id SERIAL PRIMARY KEY,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        stage_id INTEGER NOT NULL,
                        flag_submitted VARCHAR(256) NOT NULL,
                        solved_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(user_id, stage_id)
                    );
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


CHALLENGES_DATA = [
    {
        "id": 1,
        "slug": "recon-01",
        "title": "Exposed Staging Repository",
        "category": "OSINT / Recon",
        "difficulty": "Easy",
        "points": 100,
        "briefing": "The CartBreach logistics development team maintains an internal mirror repository. During a deployment commit, an engineer inadvertently committed an authentication token before pushing a quick revert.",
        "target_info": {
            "type": "Git Mirror & Storefront Health API",
            "endpoints": [
                "http://localhost:8080/cartbreach/storefront-web.git",
                "http://localhost/api/v1/health",
            ],
            "commands": [
                "git clone http://localhost:8080/cartbreach/storefront-web.git",
                'curl -H "Authorization: Bearer <staging_token>" http://localhost/api/v1/health',
            ],
        },
        "instructions": [
            "Clone the public staging repository mirror from port 8080.",
            "Inspect git commit log diffs (e.g., git log -p -S 'Bearer') to locate the leaked staging authorization token.",
            "Extract the token (cb_staging_...) and make an authenticated GET request to http://localhost/api/v1/health to recover the flag.",
        ],
        "hints": [
            "Check commits touching authentication or server config files with 'git log -p'.",
            "Use 'git log -p -S \"Bearer\"' to find commits that introduced or removed bearer credentials.",
        ],
        "flag": "SLIIT{c4rt_br34ch_g1t_c0mm1t_l34k}",
    },
    {
        "id": 2,
        "slug": "access-02",
        "title": "Broken Object Authorization",
        "category": "Web Security (BOLA)",
        "difficulty": "Easy",
        "points": 150,
        "briefing": "The Storefront fulfillment web service enables authenticated customers to view order statuses. However, the order retrieval endpoint does not enforce object-level ownership checks.",
        "target_info": {
            "type": "Web Application (Storefront)",
            "endpoints": [
                "http://localhost/login",
                "http://localhost/api/orders?order_id=1001",
            ],
            "commands": [
                'curl -X POST http://localhost/login -H "Content-Type: application/json" -d \'{"username":"guest","password":"guest123"}\' -c cookies.txt',
                "curl -b cookies.txt 'http://localhost/api/orders?order_id=1001'",
            ],
        },
        "instructions": [
            "Authenticate to the storefront via POST /login using test credentials: guest / guest123.",
            "Observe the order query pattern at /api/orders?order_id=1002.",
            "Tamper with the order_id query parameter to request administrative dispatch order #1001.",
            "Extract the flag embedded inside the shipping notes field of the order.",
        ],
        "hints": [
            "Your default assigned order is #1002. Try testing lower administrative IDs like #1001.",
            "The endpoint checks that you are signed in, but never checks if customer_id matches your account.",
        ],
        "flag": "SLIIT{c4rt_br34ch_1d0r_0rd3r_byp455}",
    },
    {
        "id": 3,
        "slug": "trust-03",
        "title": "Forged Payment Signature",
        "category": "Cryptography (HMAC)",
        "difficulty": "Moderate",
        "points": 200,
        "briefing": "CartBreach handles payment notifications via an asynchronous webhook gateway. Notifications must be cryptographically signed with HMAC-SHA256, but a sample endpoint and weak secret key allow signature forgery.",
        "target_info": {
            "type": "Payment Gateway Webhook",
            "endpoints": [
                "http://localhost/api/v1/payment/sample",
                "http://localhost/api/v1/payment/callback",
            ],
            "commands": [
                "curl http://localhost/api/v1/payment/sample",
                'curl -X POST http://localhost/api/v1/payment/callback -H "Content-Type: application/json" -H "X-Signature-SHA256: <sig>" -d \'{"order_id":1001,"status":"PAID","amount":9999.00}\'',
            ],
        },
        "instructions": [
            "Query the sample endpoint GET /api/v1/payment/sample to inspect the signature scheme and test payload.",
            "Identify the secret key ('checkout2024') used to sign payment webhooks.",
            "Construct a forged JSON payload marking administrative order #1001 as PAID with amount 9999.00.",
            "Calculate HMAC-SHA256 signature using compact JSON separators (',', ':') and send via POST /api/v1/payment/callback to receive the flag.",
        ],
        "hints": [
            "Inspect GET /api/v1/payment/sample to review the exact JSON byte formatting and signature scheme.",
            "HMAC-SHA256 signature must be computed on raw compact JSON bytes: '{\"order_id\":1001,\"status\":\"PAID\",\"amount\":9999.00}'.",
        ],
        "flag": "SLIIT{c4rt_br34ch_hm4c_51gn4tur3_f0rg3d}",
    },
    {
        "id": 4,
        "slug": "harvest-04",
        "title": "Database Snapshot Recovery",
        "category": "Digital Forensics",
        "difficulty": "Moderate",
        "points": 250,
        "briefing": "An unindexed static directory on the Storefront web server contains an orphaned database backup archive left behind during an infrastructure migration.",
        "target_info": {
            "type": "Static Backup Directory",
            "endpoints": [
                "http://localhost/static/backups/storefront_backup.sql.gz",
            ],
            "commands": [
                "curl -O http://localhost/static/backups/storefront_backup.sql.gz",
                "gunzip -c storefront_backup.sql.gz | grep -A 5 'system_service_keys'",
            ],
        },
        "instructions": [
            "Download the exposed database backup archive from /static/backups/storefront_backup.sql.gz.",
            "Decompress the gzip archive to view the SQL table definitions and data dumps.",
            "Inspect the system_service_keys table to find the encrypted service token and forensic flag.",
            "Save the internal API token (cb_internal_svc_t0k3n_4dm1n) for the next stage.",
        ],
        "hints": [
            "Download the archive with curl or your browser and decompress it using gzip / gunzip.",
            "Search the SQL dump for 'system_service_keys' or look for the flag pattern 'SLIIT{'.",
        ],
        "flag": "SLIIT{c4rt_br34ch_f0r3n51c_db_dump}",
    },
    {
        "id": 5,
        "slug": "exec-05",
        "title": "Inventory Export Injection",
        "category": "Linux System Security",
        "difficulty": "Mod-Hard",
        "points": 300,
        "briefing": "The internal Order & Inventory API exposes an invoice export feature protected by the internal service token recovered in Stage 4. An unsanitized template parameter permits OS command execution.",
        "target_info": {
            "type": "Internal Administrative API",
            "endpoints": [
                "http://localhost:8000/api/v1/admin/export",
            ],
            "commands": [
                'curl -X POST http://localhost:8000/api/v1/admin/export -H "Content-Type: application/json" -H "X-Internal-Token: cb_internal_svc_t0k3n_4dm1n" -d \'{"template_name": "; cat /home/inventory-svc/user.txt ; #"}\'',
            ],
        },
        "instructions": [
            "Target the internal inventory service with header X-Internal-Token: cb_internal_svc_t0k3n_4dm1n.",
            "Identify the template_name parameter in POST /api/v1/admin/export which is unsafely passed to a shell.",
            "Inject shell command chaining syntax (; or |) to execute commands on the container.",
            "Read /home/inventory-svc/user.txt to obtain the flag.",
        ],
        "hints": [
            "Use the internal token recovered in Stage 4: 'cb_internal_svc_t0k3n_4dm1n' in header 'X-Internal-Token'.",
            "The backend runs: echo 'Rendering template <template_name>'. Inject '; cat /home/inventory-svc/user.txt ; #'.",
        ],
        "flag": "SLIIT{c4rt_br34ch_c0mm4nd_1nj3ct_sh3ll}",
    },
    {
        "id": 6,
        "slug": "escape-06",
        "title": "Scheduled Task Escalation",
        "category": "Privilege Escalation",
        "difficulty": "Hard",
        "points": 350,
        "briefing": "Operating as inventory-svc within the inventory container, you must escalate privileges to root. Use the interactive in-browser terminal console attached to this objective. A root cron job executes a world-writable maintenance script every 2 minutes.",
        "target_info": {
            "type": "Container Host Environment & Live Terminal",
            "endpoints": [
                "http://portal.cartbreach.local/terminal/ (Interactive Web Terminal)",
                "cartbreach-inventory container /opt/scripts/sync_orders.sh",
            ],
            "commands": [
                "ls -la /opt/scripts/sync_orders.sh",
                "echo 'cp /root/root.txt /tmp/root_flag.txt && chmod 777 /tmp/root_flag.txt' >> /opt/scripts/sync_orders.sh",
                "cat /tmp/root_flag.txt",
            ],
        },
        "instructions": [
            "Open the In-Browser Web Terminal directly from this dialog or via the '>_ WEB TERMINAL' tab.",
            "Inspect /opt/scripts/sync_orders.sh and verify it is world-writable (777 permissions) and invoked by root via crontab.",
            "Append shell commands to /opt/scripts/sync_orders.sh to copy /root/root.txt to /tmp/root_flag.txt with read permissions.",
            "Wait for the root cron worker to execute the script (or monitor /var/log/sync_orders.log).",
            "Read /tmp/root_flag.txt to capture the final flag.",
        ],
        "hints": [
            "Inspect crontabs and permissions on /opt/scripts/sync_orders.sh.",
            "Append a command to the script that copies /root/root.txt to /tmp/root_flag.txt with read permissions.",
        ],
        "flag": "SLIIT{c4rt_br34ch_r00t_cr0n_pr1v35c}",
    },
]

STAGES = [
    {
        "id": s["id"],
        "slug": s["slug"],
        "title": s["title"],
        "category": s["category"],
        "difficulty": s["difficulty"],
        "points": s["points"],
    }
    for s in CHALLENGES_DATA
]


class LoginRequest(BaseModel):
    username: str
    password: str


class SubmitFlagRequest(BaseModel):
    flag: str


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


def get_user_solved_stages(user_id: int) -> set[int]:
    try:
        rows = query_database(
            "SELECT stage_id FROM challenge_solves WHERE user_id = %s",
            (user_id,),
        )
        return {row["stage_id"] for row in rows}
    except Exception:
        return set()


@app.get("/api/v1/challenges")
def list_challenges(user: dict[str, Any] = Depends(require_approved_user)) -> dict[str, Any]:
    solved_set = get_user_solved_stages(user["id"])
    result = []
    total_score = 0
    for stage in CHALLENGES_DATA:
        sid = stage["id"]
        is_solved = sid in solved_set
        if is_solved:
            status = "solved"
            total_score += stage["points"]
        elif sid == 1 or (sid - 1) in solved_set:
            status = "available"
        else:
            status = "locked"

        result.append({
            "id": stage["id"],
            "slug": stage["slug"],
            "title": stage["title"],
            "category": stage["category"],
            "difficulty": stage["difficulty"],
            "points": stage["points"],
            "status": status,
        })

    return {
        "challenges": result,
        "score": total_score,
        "solved_count": len(solved_set),
        "total_count": len(CHALLENGES_DATA),
    }


@app.get("/api/v1/challenges/{stage_id}")
def get_challenge(stage_id: int, user: dict[str, Any] = Depends(require_approved_user)) -> dict[str, Any]:
    stage = next((s for s in CHALLENGES_DATA if s["id"] == stage_id), None)
    if stage is None:
        raise HTTPException(status_code=404, detail="Challenge not found")

    solved_set = get_user_solved_stages(user["id"])
    is_solved = stage_id in solved_set
    is_available = stage_id == 1 or (stage_id - 1) in solved_set

    if not is_solved and not is_available:
        raise HTTPException(status_code=403, detail="Prerequisite challenge must be solved first")

    status = "solved" if is_solved else "available"
    return {
        "challenge": {
            "id": stage["id"],
            "slug": stage["slug"],
            "title": stage["title"],
            "category": stage["category"],
            "difficulty": stage["difficulty"],
            "points": stage["points"],
            "status": status,
            "briefing": stage["briefing"],
            "target_info": stage["target_info"],
            "instructions": stage["instructions"],
            "hints": stage["hints"],
            "solved": is_solved,
        }
    }


@app.post("/api/v1/challenges/{stage_id}/submit")
def submit_flag(stage_id: int, payload: SubmitFlagRequest, user: dict[str, Any] = Depends(require_approved_user)) -> dict[str, Any]:
    stage = next((s for s in CHALLENGES_DATA if s["id"] == stage_id), None)
    if stage is None:
        raise HTTPException(status_code=404, detail="Challenge not found")

    solved_set = get_user_solved_stages(user["id"])
    if stage_id in solved_set:
        return {
            "status": "already_solved",
            "message": "Challenge already solved!",
            "points": stage["points"],
        }

    is_available = stage_id == 1 or (stage_id - 1) in solved_set
    if not is_available:
        raise HTTPException(status_code=403, detail="Challenge is locked")

    submitted = payload.flag.strip()
    if submitted != stage["flag"]:
        raise HTTPException(status_code=400, detail="Incorrect flag. Inspect the evidence and try again.")

    try:
        query_database(
            """
            INSERT INTO challenge_solves (user_id, stage_id, flag_submitted)
            VALUES (%s, %s, %s)
            ON CONFLICT (user_id, stage_id) DO NOTHING
            """,
            (user["id"], stage_id, submitted),
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to record solve") from exc

    updated_solves = get_user_solved_stages(user["id"])
    new_score = sum(s["points"] for s in CHALLENGES_DATA if s["id"] in updated_solves)

    return {
        "status": "correct",
        "message": f"Flag accepted! +{stage['points']} PTS",
        "stage_id": stage_id,
        "points": stage["points"],
        "total_score": new_score,
        "unlocked_next": stage_id < len(CHALLENGES_DATA),
    }


@app.get("/api/v1/leaderboard")
def leaderboard(_: dict[str, Any] = Depends(require_approved_user)) -> dict[str, list[dict[str, Any]]]:
    try:
        solves = query_database("""
            SELECT u.id AS user_id, u.username, cs.stage_id, cs.solved_at
            FROM challenge_solves cs
            JOIN users u ON cs.user_id = u.id
            ORDER BY cs.solved_at ASC
        """)
    except Exception:
        solves = []

    stage_points = {s["id"]: s["points"] for s in CHALLENGES_DATA}
    user_map: dict[int, dict[str, Any]] = {}

    for row in solves:
        uid = row["user_id"]
        if uid not in user_map:
            user_map[uid] = {
                "id": uid,
                "username": row["username"],
                "score": 0,
                "solves": 0,
                "last_solve": row["solved_at"].isoformat() if row.get("solved_at") else None,
            }
        user_map[uid]["score"] += stage_points.get(row["stage_id"], 0)
        user_map[uid]["solves"] += 1
        if row.get("solved_at"):
            user_map[uid]["last_solve"] = row["solved_at"].isoformat()

    sorted_teams = sorted(user_map.values(), key=lambda x: (-x["score"], x.get("last_solve") or ""))
    for rank, team in enumerate(sorted_teams, 1):
        team["rank"] = rank

    return {"teams": sorted_teams}


@app.get("/api/v1/admin/stats")
def admin_stats(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    try:
        user_counts = query_database("SELECT status, count(*) AS count FROM users GROUP BY status")
        solves_count = query_database("SELECT count(*) AS total_solves FROM challenge_solves")
        total_solves = solves_count[0]["total_solves"] if solves_count else 0
        status_map = {row["status"]: row["count"] for row in user_counts}
    except Exception:
        status_map = {}
        total_solves = 0

    return {
        "users": status_map,
        "total_solves": total_solves,
    }


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

