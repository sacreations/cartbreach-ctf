# CartBreach: Microservice Supply-Chain Infiltration CTF Play Box
### Module: IE3132 - Penetration Testing (2026) | Assignment 02

CartBreach is a production-grade, 6-stage Capture The Flag (CTF) play box simulating an end-to-end supply-chain compromise of an enterprise e-commerce platform. It provides hands-on evaluation across **6 distinct cybersecurity domains**, strictly enforcing network segmentation, container hardening, automated flag validation, state recovery, and individual automated exploit chains.

---

## 1. Group Member Allocation & Contribution Matrix

| Member | Student ID (IT Number) | Full Name | Primary Assigned Role | Assigned Deliverable & Individual LO3 Automation Script |
| :--- | :--- | :--- | :--- | :--- |
| **Member 1** | `IT24103925` | `Rathnayaka R.M.S.A` | Platform Architect & Security Administrator | Platform Architecture, Docker Network Segmentation, Container Hardening, Flag Engine & `scripts/platform_verify.py` |
| **Member 2** | `IT24102810` | `Fernando.W.M.S` | Challenge Designer A (Initial Access & Web) | Stages 1–3 Design & LO3 Solvers: `solvers/stage1_recon_solver.py`, `stage2_bola_order_exploit.py`, `stage3_crypto_hmac_forge.py` |
| **Member 3** | `IT24103785` | `Wimaladharma S.T.C.D` | Challenge Designer B (Forensics, Pivot & Privesc) | Stages 4–6 Design & LO3 Solvers: `solvers/stage4_forensics_db_carver.py`, `stage5_cmd_injection_exploit.py`, `stage6_root_privesc_exploit.py` |
| **Member 4** | `IT24100490` | `Fernando G.N.N ` | Quality Assurance & Integration Testing | End-to-End Orchestration (`solvers/solve_all_e2e.py`), Test Suite (`tests/`), Unintended Solution Defense & Assignment 01 Evolution |

---

## 2. Learning Outcomes (LO) Alignment Matrix

| Learning Outcome | Assessment Criteria | Implementation in CartBreach | Responsible Members |
| :--- | :--- | :--- | :--- |
| **LO1: Design & Architecture** | Deploy a resilient, multi-stage CTF environment spanning $\ge 4$ distinct security domains with network isolation. | 6 challenge stages across 6 domains (OSINT, Web Security, Cryptography, Digital Forensics, Linux System Security, Privilege Escalation). Dual Docker networks (`cartbreach-public` vs `cartbreach-backend` with `internal: true`). Non-root container accounts (UID 1001) and strict CPU/memory caps. | **Member 1, Member 2, Member 3** |
| **LO2: Security Administration** | Implement dynamic challenge management, anti-tamper flag verification, participant telemetry, and automated environment resets. | FastAPI Platform API with SQLite/Postgres solve telemetry, Admin Challenge Status Matrix (`/admin`), single-click user/stage resets, and idempotent automated host recovery via `scripts/reset.sh`. | **Member 1, Member 4** |
| **LO3: Exploit Automation & Verification** | Develop and demonstrate functional, self-developed automated scripts for exploitation, auditing, and end-to-end evaluation. | Standalone CLI solvers for each stage (`solvers/stage1`–`stage6`), platform security auditor (`scripts/platform_verify.py`), master integration harness (`solvers/solve_all_e2e.py`), and 28+ automated unit/boundary tests. | **Member 1, Member 2, Member 3, Member 4** |

---

## 3. Challenge Progression & Domain Matrix

| Stage | Title / Identifier | Domain | MITRE ATT&CK Mapping | Difficulty | Target Endpoint / Service | Flag Format |
| :---: | :--- | :--- | :--- | :---: | :--- | :--- |
| **1** | Exposed Staging Repo (`recon-01`) | OSINT / Reconnaissance | T1552.004 (Private Keys / Secrets in Code) | Easy | `http://localhost:8080/cartbreach/storefront-web.git` | `SLIIT{c4rt_br34ch_g1t_c0mm1t_l34k}` |
| **2** | Broken Object Auth (`access-02`) | Web Application Security (BOLA) | T1078 (Valid Accounts / Insecure Direct Object Ref) | Easy | `http://localhost/api/orders?order_id=1001` | `SLIIT{c4rt_br34ch_1d0r_0rd3r_byp455}` |
| **3** | Forged Payment Sig (`trust-03`) | Applied Cryptography | T1565.002 (Transmitted Data Manipulation) | Moderate | `http://localhost/api/v1/payment/callback` | `SLIIT{c4rt_br34ch_hm4c_51gn4tur3_f0rg3d}` |
| **4** | DB Snapshot Recovery (`harvest-04`) | Digital Forensics | T1005 (Data from Local System / Artifact Carving) | Moderate | `http://localhost/static/backups/storefront_backup.sql.gz` | `SLIIT{c4rt_br34ch_f0r3n51c_db_dump}` |
| **5** | Inventory Export Injection (`exec-05`) | Linux System Security | T1059.004 (Unix Shell Command Injection) | Mod-Hard | `http://localhost:8000/api/v1/admin/export` | `SLIIT{c4rt_br34ch_c0mm4nd_1nj3ct_sh3ll}` |
| **6** | Scheduled Task Escalation (`escape-06`) | Linux Privilege Escalation | T1053.003 (Cron Task Hijacking) | Hard | `http://portal.cartbreach.local/terminal/` (Container PTY) | `SLIIT{c4rt_br34ch_r00t_cr0n_pr1v35c}` |

---

## 4. Platform Network Topology & Security Architecture

```
                          [ External Host / Internet ]
                                       │
                       ┌───────────────┴───────────────┐
                       │ Port 80 (HTTP) & 8080 (Git)   │
                       ▼                               ▼
      ┌─────────────────────────────────────────────────────────────────┐
      │             cartbreach-nginx-proxy (Reverse Proxy)              │
      └────────────────────────────────┬────────────────────────────────┘
                                       │
    ═══════════════════════════════════╪════════════════════════════════════════ (cartbreach-public: 172.28.10.0/24)
          │                            │                       │
          ▼                            ▼                       ▼
┌──────────────────┐         ┌──────────────────┐    ┌──────────────────┐
│ participant-     │         │ storefront-web   │    │ staging-repo     │
│ portal (UI)      │         │ (Node.js :3000)  │    │ (Smart HTTP :8080│
└──────────────────┘         └─────────┬────────┘    └──────────────────┘
                                       │
    ═══════════════════════════════════╪════════════════════════════════════════ (cartbreach-backend: 172.28.20.0/24, internal: true)
          │                            │                       │
          ▼                            ▼                       ▼
┌──────────────────┐         ┌──────────────────┐    ┌──────────────────┐
│ platform-api     │         │ postgres-data    │    │ order-inventory- │
│ (FastAPI :8000)  │         │ (PostgreSQL:5432)│    │ api (Web Terminal│
│ [UID 1001]       │         │ [ISOLATED]       │    │  & Cron Worker)  │
└──────────────────┘         └──────────────────┘    └──────────────────┘
```

### Security Isolation Controls
1. **Dual Docker Bridge Networks**: Public web traffic is strictly isolated from internal backend communication.
2. **Internal Network Boundary (`internal: true`)**: The `cartbreach-backend` subnet (`172.28.20.0/24`) has no external gateway routing. The PostgreSQL database (port 5432) cannot be queried directly from the host.
3. **Least Privilege Execution**: Services (`platform-api`, `order-inventory-api`) execute under dedicated unprivileged system users (`UID 1001:1001`).
4. **Container Quotas & DoS Mitigation**: CPU usage is capped at `0.25` to `0.50` cores per container; RAM is capped between `128MB` and `384MB` to prevent resource starvation or container fork-bombs.
5. **No New Privileges**: Configured with `security_opt: [no-new-privileges:true]` across user containers to prevent setuid elevation.

---

## 5. Justification of Design Changes from Assignment 01

| Dimension | Assignment 01 Design | Assignment 02 Improved Implementation | Technical Justification & Security Rationale |
| :--- | :--- | :--- | :--- |
| **Stage 6 Access Vector** | Required local OpenSSH client keys and port-forwarded SSH daemon. | Integrated Cyber-Ops **In-Browser Web Terminal** (`ttyd` + WebSocket over Nginx). | Eliminates cross-platform SSH configuration issues (Windows PuTTY vs Linux SSH) and firewall blocks on university networks. Provides instant, sandboxed PTY terminal access directly inside the challenge portal. |
| **Authentication & Access Governance** | Static hardcoded participant credentials stored in local cookies. | Integrated **Google OAuth 2.0** with **Administrator Approval Gate**. | Enforces enterprise zero-trust identity management. Prevents rogue participant signups by requiring administrator sign-off before challenge board access is unlocked. |
| **Host Routing & Cloud Deployment** | Hardcoded `localhost` URLs in all frontend HTML/API templates. | **Dynamic Domain Resolution Engine** supporting Cloudflare Tunnels & custom domains. | When deployed on cloud VMs or reverse-tunneled via Cloudflare (`trycloudflare.com`), endpoints dynamically resolve to public hostnames rather than broken localhost references. |
| **Administrative Control Plane** | Manual command-line Docker container restarts for resets. | **Admin Challenge Matrix & Granular Reset Engine** in Portal UI. | Administrators can monitor live participant progression per stage and execute one-click stage or user challenge resets without restarting Docker containers. |
| **Solver Automation** | Manual step-by-step documentation in text files. | **Modular Standalone Python Solvers** (`solvers/`) & E2E Validation Harness. | Satisfies individual LO3 requirements, enabling repeatable, automated verification of all challenge paths in under 30 seconds. |

---

## 6. Project Risk Register

| Risk ID | Identified Risk Scenario | Likelihood | Impact | Severity | Implemented Technical Mitigation Strategy |
| :---: | :--- | :---: | :---: | :---: | :--- |
| **R-01** | **Container Breakout during Stage 6 Exploitation** | Low | High | Medium | Containers run with `security_opt: [no-new-privileges:true]`, dropping Linux capabilities (`cap_drop: ALL`). Web terminal executes as UID 1001 without host filesystem mounts. |
| **R-02** | **Denial of Service via Aggressive Brute-Forcing** | Medium | Medium | Medium | Docker Compose defines hard `mem_limit` (128M–384M) and `cpus` (0.25–0.50) limits. Nginx reverse proxy enforces connection rate limits. |
| **R-03** | **State Corruption / Data Loss during Penetration Testing** | High | Medium | Medium | Automated idempotent reset scripts (`scripts/reset.sh`) flush dynamic tables and restore seed data in < 15 seconds without container rebuilds. |
| **R-04** | **Unintended Solution Shortcuts Bypassing Prerequisite Stages** | Medium | High | High | FastAPI platform API enforces prerequisite unlock logic (e.g. Stage 3 requires 1 & 2 solved). Flags are validated using non-leaking server-side variables. |
| **R-05** | **Exposure of Internal PostgreSQL / Microservice Ports to Host** | Low | Critical | High | Dual Docker networks configure `cartbreach-backend` with `internal: true`. Host socket checks verify port 5432 is strictly unreachable. |

---

## 7. Examiner Quickstart & Deployment Guide

### Prerequisites
- Docker Engine 24.x+ & Docker Compose v2
- Python 3.10+ (for running solver and automated test scripts)
- Git

### Step 1: Clone Repository & Configure Environment
```bash
git clone <repository-url> cartbreach-ctf
cd cartbreach-ctf

# Copy environment template
cp cartbreach.env.example cartbreach.env
```

### Step 2: Configure Local DNS Hosts (Optional for local domain routing)
Add the following line to `/etc/hosts` (Linux/macOS) or `C:\Windows\System32\drivers\etc\hosts` (Windows):
```text
127.0.0.1 cartbreach.local portal.cartbreach.local admin.cartbreach.local git.cartbreach.local
```

### Step 3: Launch Docker Ecosystem
```bash
docker compose --env-file cartbreach.env up -d --build
```

Verify that all 8 containers are running and healthy:
```bash
docker compose ps
```

---

## 8. Automated Testing & Verification Suite

### Running the LO3 Standalone Solvers
Each group member's exploit script can be tested independently:

```bash
# Member 2 LO3 Scripts (Stages 1 - 3)
python3 solvers/stage1_recon_solver.py
python3 solvers/stage2_bola_order_exploit.py
python3 solvers/stage3_crypto_hmac_forge.py

# Member 3 LO3 Scripts (Stages 4 - 6)
python3 solvers/stage4_forensics_db_carver.py
python3 solvers/stage5_cmd_injection_exploit.py
python3 solvers/stage6_root_privesc_exploit.py

# Member 4 LO3 Master E2E Exploit Harness (All Stages)
python3 solvers/solve_all_e2e.py
```

### Running Member 1 Platform Security Auditor
```bash
python3 scripts/platform_verify.py
```

### Running Automated Pytest Validation Suites
```bash
# 1. Challenge workflow, progression, and administration tests (23 tests)
pytest tests/test_challenge_workflow.py -v

# 2. Unintended solution defense and boundary checks
pytest tests/test_unintended_solutions.py -v

# 3. Environment reset and state recovery tests
pytest tests/test_reset_recovery.py -v
```

### Demonstrating Environment State Reset
```bash
bash scripts/reset.sh
```

---

## 10. Educational Safety & Ethics Notice
*CartBreach is developed strictly for educational cybersecurity instruction and authorized academic evaluation within the SLIIT IE3132 Penetration Testing module. All vulnerabilities and exploits are contained within sandboxed Docker network namespaces.*
