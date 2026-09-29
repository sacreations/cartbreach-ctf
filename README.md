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

### 1. Launch the CTF Stack
```bash
cd cartbreach-ctf
docker compose up -d --build
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
