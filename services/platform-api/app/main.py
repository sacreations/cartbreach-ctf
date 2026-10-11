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
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response
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
            "service": "Git Mirror & Storefront Health API",
            "protocol": "HTTP / Git Version Control",
            "endpoints": [
                "http://localhost:8080/cartbreach/storefront-web.git",
                "http://git.cartbreach.local:8080/cartbreach/storefront-web.git",
                "http://localhost/api/v1/health",
            ],
            "auth_context": "Anonymous Git clone; Bearer Token required on /api/v1/health",
        },
        "suggested_tools": ["git", "curl", "trufflehog", "gitleaks"],
        "instructions": [
            "Clone and examine the public Git mirror repository using the provided endpoint.",
            "Audit commit history and patch diffs for inadvertently committed authentication credentials.",
            "Validate the discovered credential against the storefront API health check endpoint to recover the flag.",
        ],
        "hints": [
            "Developers often push quick revert commits when secrets leak, but Git maintains the full revision graph.",
            "Investigate Git log filters or search flags (such as -S pickaxe or -G regex) to trace additions and removals of authorization headers across all commits.",
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
            "service": "Storefront Web Portal & Customer Order API",
            "protocol": "HTTP REST",
            "endpoints": [
                "http://localhost/login",
                "http://localhost/api/orders?order_id=<id>",
            ],
            "auth_context": "Test Account: guest / guest123",
        },
        "suggested_tools": ["burpsuite", "caido", "curl", "browser devtools", "owasp-zap"],
        "instructions": [
            "Authenticate to the storefront using the provided guest test credentials.",
            "Intercept and inspect the HTTP traffic generated when requesting customer order records.",
            "Probe order identifier parameters to test access control boundaries across other customer and administrative records.",
            "Inspect the retrieved record attributes to identify confidential dispatch metadata containing the flag.",
        ],
        "hints": [
            "Examine whether the application verifies that the authenticated user is the legitimate owner of the requested order ID.",
            "Sequential or predictable identifiers are prime candidates for horizontal and vertical authorization bypass.",
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
            "service": "Asynchronous Payment Gateway Webhook Listener",
            "protocol": "HTTP REST / JSON Webhooks",
            "endpoints": [
                "http://localhost/api/v1/payment/sample",
                "http://localhost/api/v1/payment/callback",
            ],
            "auth_context": "Header: X-Signature-SHA256 (<hex_signature>)",
        },
        "suggested_tools": ["cyberchef", "python (hashlib, hmac)", "burpsuite", "curl"],
        "instructions": [
            "Review the reference sample endpoint to understand the webhook payload schema and signature specification.",
            "Inspect the sample response metadata to discover the shared secret key and signing algorithm.",
            "Craft a modified webhook transaction marking the target administrative order (#1001) as paid with the full invoice value.",
            "Generate a valid HMAC-SHA256 signature for your payload and transmit it to the callback receiver.",
        ],
        "hints": [
            "Inspect the sample response payload carefully—development configurations frequently disclose default signing keys in debug outputs.",
            "When computing HMAC digests on JSON data, serialization formatting (whitespace, delimiters, character encoding) must strictly match what the receiving server parses.",
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
            "service": "Storefront Static File Server",
            "protocol": "HTTP Static Assets",
            "endpoints": [
                "http://localhost/static/backups/storefront_backup.sql.gz",
            ],
            "auth_context": "Anonymous Static File Download",
        },
        "suggested_tools": ["curl", "wget", "gzip / gunzip", "strings", "grep", "file"],
        "instructions": [
            "Retrieve the exposed compressed database snapshot from the static web storage path.",
            "Decompress and inspect the archive structure to analyze database schemas and table contents.",
            "Perform forensic analysis on credential and key tables to uncover internal service authorization tokens and the challenge flag.",
            "Note any internal administrative service tokens for subsequent privilege escalation stages.",
        ],
        "hints": [
            "Decompress the downloaded archive using standard archive utilities to inspect raw SQL statements.",
            "Look for database tables dedicated to internal service integration, machine-to-machine tokens, or cryptographic keys.",
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
            "service": "Internal Order & Inventory Administrative API",
            "protocol": "HTTP REST",
            "endpoints": [
                "http://localhost:8000/api/v1/admin/export",
            ],
            "auth_context": "Header: X-Internal-Token (<internal_service_token_from_stage_4>)",
        },
        "suggested_tools": ["burpsuite", "curl", "postman", "python-requests"],
        "instructions": [
            "Target the internal inventory export endpoint using the internal service token acquired from the forensic snapshot.",
            "Analyze the JSON parameters accepted by the export endpoint to identify fields reflected in backend processing.",
            "Construct a command injection vector using shell metacharacters to execute arbitrary operating system commands.",
            "Read the unprivileged user flag located in the service user's home directory (/home/inventory-svc/).",
        ],
        "hints": [
            "Test how the application handles shell command delimiters (such as semicolons, pipes, or command substitution) within template string inputs.",
            "The command runs under the context of the inventory-svc user. Explore standard Unix paths to locate flag files.",
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
        "briefing": "Operating as inventory-svc within the inventory container, you must escalate privileges to root. Use the interactive in-browser terminal console attached to this objective. A root cron job executes a world-writable maintenance script periodically.",
        "target_info": {
            "service": "Live Container PTY / Interactive Terminal",
            "protocol": "WebSocket / Terminal (PTY)",
            "endpoints": [
                "http://portal.cartbreach.local/terminal/ (Interactive Web Terminal)",
                "cartbreach-inventory container environment",
            ],
            "auth_context": "Starting Session: inventory-svc (UID 1001)",
        },
        "suggested_tools": ["linpeas.sh", "pspy", "crontab", "find", "ls", "bash"],
        "instructions": [
            "Open the In-Browser Web Terminal directly from this dialog or via the '>_ WEB TERMINAL' tab.",
            "Perform local Linux privilege escalation enumeration: inspect file permissions, system cron jobs, background processes, and scheduled tasks.",
            "Identify any world-writable scripts executed with elevated privileges (root context).",
            "Hijack the identified maintenance routine to execute privileged commands and retrieve the final root flag from /root/root.txt.",
        ],
        "hints": [
            "Audit write permissions across /opt/ and /etc/ directories to check for files writable by the unprivileged group or world.",
            "Monitor system logs in /var/log/ or inspect /etc/crontab to observe scheduled task frequency and the executing user context.",
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


def get_effective_google_redirect_uri(request: Request | None = None) -> str:
    default_local_uri = "http://portal.cartbreach.local/api/v1/auth/google/callback"
    custom_uri = os.getenv("GOOGLE_REDIRECT_URI", "").strip()
    if custom_uri and custom_uri != default_local_uri:
        return custom_uri

    if request is not None:
        host = (
            request.headers.get("x-forwarded-host")
            or request.headers.get("host")
            or ""
        ).split(":")[0].strip().lower()
        proto = (request.headers.get("x-forwarded-proto") or "").strip().lower()
        local_indicators = ("localhost", "127.0.0.1", "cartbreach.local", ".local")
        if host and not any(host.endswith(loc) or host == loc for loc in local_indicators):
            scheme = proto or "https"
            return f"{scheme}://{host}/api/v1/auth/google/callback"

    return custom_uri or default_local_uri


@app.get("/api/v1/auth/google/login")
def google_login(request: Request) -> RedirectResponse:
    if GOOGLE_CLIENT_ID:
        state = secrets.token_urlsafe(16)
        oauth_states[state] = time.time() + 600
        redirect_uri = get_effective_google_redirect_uri(request)
        params = {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": redirect_uri,
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
    request: Request,
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
        redirect_uri = get_effective_google_redirect_uri(request)
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_res = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "code": code,
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uri": redirect_uri,
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


def resolve_stage_endpoints(stage_id: int, request: Request | None = None) -> list[str]:
    public_domain = os.getenv("PUBLIC_DOMAIN", "").strip()
    public_scheme = os.getenv("PUBLIC_SCHEME", "https").strip().lower()
    public_storefront_url = os.getenv("PUBLIC_STOREFRONT_URL", "").strip().rstrip("/")
    public_git_url = os.getenv("PUBLIC_GIT_URL", "").strip().rstrip("/")
    public_portal_url = os.getenv("PUBLIC_PORTAL_URL", "").strip().rstrip("/")
    public_inventory_url = os.getenv("PUBLIC_INVENTORY_URL", "").strip().rstrip("/")

    base_domain = public_domain
    scheme = public_scheme or "https"

    if request is not None:
        host_header = (
            request.headers.get("x-forwarded-host")
            or request.headers.get("host")
            or ""
        ).split(":")[0].strip().lower()

        proto_header = (
            request.headers.get("x-forwarded-proto")
            or ""
        ).strip().lower()

        if not proto_header and "cf-visitor" in request.headers:
            try:
                import json
                proto_header = json.loads(request.headers["cf-visitor"]).get("scheme", "")
            except Exception:
                pass

        if proto_header:
            scheme = proto_header

        local_indicators = (
            "localhost",
            "127.0.0.1",
            "testclient",
            "cartbreach.local",
            ".local",
        )
        is_local_host = (
            not host_header
            or any(host_header.endswith(ind) or host_header == ind for ind in local_indicators)
            or host_header.startswith("192.168.")
            or host_header.startswith("10.")
            or host_header.startswith("172.")
        )

        if not is_local_host and not base_domain:
            for prefix in ("portal.", "admin.", "git.", "store.", "shop.", "inventory.", "api."):
                if host_header.startswith(prefix):
                    base_domain = host_header[len(prefix):]
                    break
            if not base_domain:
                base_domain = host_header

    has_public = bool(base_domain or public_storefront_url or public_git_url or public_inventory_url or public_portal_url)

    store_url = public_storefront_url or (f"{scheme}://store.{base_domain}" if base_domain else "")
    git_url = public_git_url or (f"{scheme}://git.{base_domain}" if base_domain else "")
    inv_url = public_inventory_url or (f"{scheme}://inventory.{base_domain}" if base_domain else "")
    portal_url = public_portal_url or (f"{scheme}://portal.{base_domain}" if base_domain else "")

    stage_definitions: dict[int, dict[str, list[str]]] = {
        1: {
            "hosted": [
                f"{git_url}/cartbreach/storefront-web.git",
                f"{store_url}/api/v1/health",
            ],
            "local": [
                "http://localhost:8080/cartbreach/storefront-web.git",
                "http://git.cartbreach.local:8080/cartbreach/storefront-web.git",
                "http://localhost/api/v1/health",
            ],
        },
        2: {
            "hosted": [
                f"{store_url}/login",
                f"{store_url}/api/orders?order_id=<id>",
            ],
            "local": [
                "http://localhost/login",
                "http://localhost/api/orders?order_id=<id>",
            ],
        },
        3: {
            "hosted": [
                f"{store_url}/api/v1/payment/sample",
                f"{store_url}/api/v1/payment/callback",
            ],
            "local": [
                "http://localhost/api/v1/payment/sample",
                "http://localhost/api/v1/payment/callback",
            ],
        },
        4: {
            "hosted": [
                f"{store_url}/static/backups/storefront_backup.sql.gz",
            ],
            "local": [
                "http://localhost/static/backups/storefront_backup.sql.gz",
            ],
        },
        5: {
            "hosted": [
                f"{inv_url}/api/v1/admin/export",
            ],
            "local": [
                "http://localhost:8000/api/v1/admin/export",
                "http://inventory.cartbreach.local/api/v1/admin/export",
            ],
        },
        6: {
            "hosted": [
                f"{portal_url}/terminal/ (Interactive Web Terminal)",
                "cartbreach-inventory container environment",
            ],
            "local": [
                "http://portal.cartbreach.local/terminal/ (Interactive Web Terminal)",
                "cartbreach-inventory container environment",
            ],
        },
    }

    config = stage_definitions.get(stage_id)
    if not config:
        return []

    local_endpoints = config["local"]
    if not has_public:
        return local_endpoints

    hosted_endpoints = [ep for ep in config["hosted"] if not ep.startswith("/")]

    combined: list[str] = []
    for ep in hosted_endpoints:
        if ep == "cartbreach-inventory container environment":
            continue
        combined.append(f"[PUBLIC] {ep}")

    for ep in local_endpoints:
        if ep == "cartbreach-inventory container environment":
            combined.append(ep)
        else:
            combined.append(f"[LOCAL]  {ep}")

    return combined


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
def get_challenge(
    stage_id: int,
    request: Request,
    user: dict[str, Any] = Depends(require_approved_user),
) -> dict[str, Any]:
    stage = next((s for s in CHALLENGES_DATA if s["id"] == stage_id), None)
    if stage is None:
        raise HTTPException(status_code=404, detail="Challenge not found")

    solved_set = get_user_solved_stages(user["id"])
    is_solved = stage_id in solved_set
    is_available = stage_id == 1 or (stage_id - 1) in solved_set

    if not is_solved and not is_available:
        raise HTTPException(status_code=403, detail="Prerequisite challenge must be solved first")

    status = "solved" if is_solved else "available"
    target_info = dict(stage["target_info"])
    target_info["endpoints"] = resolve_stage_endpoints(stage["id"], request)

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
            "target_info": target_info,
            "suggested_tools": stage.get("suggested_tools", []),
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
    try:
        user_solves = query_database(
            "SELECT user_id, stage_id FROM challenge_solves ORDER BY stage_id ASC"
        )
        solves_by_user: dict[int, list[int]] = {}
        for s in user_solves:
            uid = s["user_id"]
            if uid not in solves_by_user:
                solves_by_user[uid] = []
            solves_by_user[uid].append(s["stage_id"])
    except Exception:
        solves_by_user = {}

    clean_users = [
        {
            "id": u["id"],
            "username": u["username"],
            "email": u.get("email"),
            "role": u["role"],
            "status": u.get("status", "approved"),
            "auth_provider": u.get("auth_provider", "local"),
            "created_at": u["created_at"].isoformat() if u.get("created_at") else None,
            "solved_stages": solves_by_user.get(u["id"], []),
            "solve_count": len(solves_by_user.get(u["id"], [])),
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


@app.get("/api/v1/admin/challenges")
def admin_challenges_status(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    try:
        solves_rows = query_database("""
            SELECT cs.stage_id, cs.user_id, cs.solved_at, u.username
            FROM challenge_solves cs
            JOIN users u ON cs.user_id = u.id
            ORDER BY cs.solved_at ASC
        """)
        users_count = query_database(
            "SELECT count(*) AS total_users, count(*) FILTER (WHERE status = 'approved' AND role = 'participant') AS approved_participants FROM users"
        )
    except Exception:
        solves_rows = []
        users_count = []

    approved_participants = users_count[0]["approved_participants"] if users_count else 0
    total_users = users_count[0]["total_users"] if users_count else 0

    solves_by_stage: dict[int, list[dict[str, Any]]] = {stage["id"]: [] for stage in CHALLENGES_DATA}
    solvers_by_user: dict[int, set[int]] = {}

    for row in solves_rows:
        sid = row["stage_id"]
        uid = row["user_id"]
        if sid in solves_by_stage:
            solves_by_stage[sid].append({
                "user_id": uid,
                "username": row["username"],
                "solved_at": row["solved_at"].isoformat() if row.get("solved_at") else None,
            })
        if uid not in solvers_by_user:
            solvers_by_user[uid] = set()
        solvers_by_user[uid].add(sid)

    stages = []
    total_possible_stages = len(CHALLENGES_DATA)
    completed_all_count = sum(1 for stages_set in solvers_by_user.values() if len(stages_set) == total_possible_stages)

    for stage in CHALLENGES_DATA:
        sid = stage["id"]
        stage_solves = solves_by_stage.get(sid, [])
        solve_count = len(stage_solves)
        solve_rate = round((solve_count / approved_participants * 100), 1) if approved_participants > 0 else 0.0

        stages.append({
            "id": sid,
            "slug": stage["slug"],
            "title": stage["title"],
            "category": stage["category"],
            "difficulty": stage["difficulty"],
            "points": stage["points"],
            "solve_count": solve_count,
            "solve_rate": solve_rate,
            "recent_solvers": stage_solves[-5:],
            "solvers": stage_solves,
        })

    return {
        "stages": stages,
        "total_stages": total_possible_stages,
        "total_solves": len(solves_rows),
        "total_users": total_users,
        "approved_participants": approved_participants,
        "completed_all_count": completed_all_count,
    }


@app.post("/api/v1/admin/users/{user_id}/reset-challenges")
def reset_user_challenges(user_id: int, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    users = query_database("SELECT id, username FROM users WHERE id = %s", (user_id,))
    if not users:
        raise HTTPException(status_code=404, detail="User not found")
    user = users[0]

    deleted = query_database(
        "DELETE FROM challenge_solves WHERE user_id = %s RETURNING stage_id",
        (user_id,),
    )
    return {
        "status": "ok",
        "message": f"Successfully reset challenges for user {user['username']}",
        "user_id": user_id,
        "username": user["username"],
        "cleared_count": len(deleted),
        "cleared_stages": sorted([r["stage_id"] for r in deleted]),
    }


@app.post("/api/v1/admin/users/{user_id}/reset-challenges/{stage_id}")
def reset_user_stage(user_id: int, stage_id: int, _: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    users = query_database("SELECT id, username FROM users WHERE id = %s", (user_id,))
    if not users:
        raise HTTPException(status_code=404, detail="User not found")
    user = users[0]

    deleted = query_database(
        "DELETE FROM challenge_solves WHERE user_id = %s AND stage_id = %s RETURNING stage_id",
        (user_id, stage_id),
    )
    return {
        "status": "ok",
        "message": f"Successfully reset stage {stage_id} for user {user['username']}",
        "user_id": user_id,
        "stage_id": stage_id,
        "cleared": bool(deleted),
    }


@app.post("/api/v1/admin/challenges/reset-all")
def reset_all_challenges(_: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    deleted = query_database("DELETE FROM challenge_solves RETURNING id")
    return {
        "status": "ok",
        "message": f"Successfully reset all challenge solves ({len(deleted)} cleared)",
        "cleared_count": len(deleted),
    }

