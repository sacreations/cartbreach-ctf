# CartBreach: Microservice Supply-Chain Infiltration

CartBreach is a 6-stage Capture The Flag (CTF) play box designed for the **IE3132 Penetration Testing** module at SLIIT. It models a realistic supply-chain breach against an enterprise e-commerce and microservices fulfillment ecosystem.

---

## Architecture Overview

- **Edge Proxy:** Nginx reverse proxy (public subnet: `172.28.10.0/24`, ports `80` and `8080`).
- **Internal Backend:** Isolated internal bridge network (`172.28.20.0/24`, `internal: true`) with no egress routing.
- **Microservices:**
  - `staging-repo`: Git HTTP mirror on port `8080` (Stage 1: RECON-01).
  - `storefront-web`: Node.js Express application (Stage 2: WEB-01 BOLA & Stage 4: FORENSIC-01 SQL dump).
  - `payment-gw`: Python Flask asynchronous payment gateway (Stage 3: CRYPTO-01 weak HMAC-SHA256).
  - `order-inventory-api`: Python FastAPI administrative API with command injection and root cron job (Stage 5: SYS-01 & Stage 6: ROOT-01).
  - `postgres-data`: PostgreSQL 16 database backend.
  - `platform-api`: Trusted FastAPI control plane for challenge metadata and health checks.
  - `participant-portal`: Participant challenge board at `portal.cartbreach.local`.
  - `admin-dashboard`: Operations dashboard at `admin.cartbreach.local`.

---

## Challenge Progression

| Stage | Title | Domain | Difficulty | Flag Format |
|---|---|---|---|---|
| 1 | RECON-01 | OSINT / Recon | Easy | `SLIIT{c4rt_br34ch_g1t_c0mm1t_l34k}` |
| 2 | WEB-01 | Web Security (BOLA) | Easy | `SLIIT{c4rt_br34ch_1d0r_0rd3r_byp455}` |
| 3 | CRYPTO-01 | Cryptography (HMAC) | Moderate | `SLIIT{c4rt_br34ch_hm4c_51gn4tur3_f0rg3d}` |
| 4 | FORENSIC-01 | Digital Forensics | Moderate | `SLIIT{c4rt_br34ch_f0r3n51c_db_dump}` |
| 5 | SYS-01 | Linux System Security | Mod-Hard | `SLIIT{c4rt_br34ch_c0mm4nd_1nj3ct_sh3ll}` |
| 6 | ROOT-01 | Privilege Escalation | Hard | `SLIIT{c4rt_br34ch_r00t_cr0n_pr1v35c}` |

---

## Quickstart

### Prerequisites
- Docker Engine 24.x+ & Docker Compose v2
- Python 3.10+ (for running the automated test suite)

### 1. Configure the local environment

`cartbreach.env` contains local challenge credentials and must not be committed. Copy it from a secure local source or create an untracked file with the required values. Docker Compose automatically reads `.env`; when using `cartbreach.env` explicitly, run:

```bash
docker compose --env-file cartbreach.env up -d --build
```

Never publish real credentials, production secrets, or private keys in this repository. The values used by this educational CTF are intentionally weak challenge fixtures, but they should still remain untracked.

### 2. Launch the CTF Stack
```bash
cd cartbreach-ctf
docker compose --env-file cartbreach.env up -d --build
```

For local host-based routing, add these entries to your hosts file:

```text
127.0.0.1 cartbreach.local portal.cartbreach.local admin.cartbreach.local git.cartbreach.local
```

### 2. Verify Health
```bash
./scripts/healthcheck.sh
```

### 3. Run Automated Validation Test Suite
```bash
pip install -r tests/requirements.txt
pytest tests/ -v
```

### 4. Automated Environment Reset
Reset the environment every 30 minutes via:
```bash
./scripts/reset.sh
```
