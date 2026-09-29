"""Stage 3: CRYPTO-01 — Tampered Callback (HMAC-SHA256 Forgery)."""
import hmac
import hashlib
import json
import requests

BASE_URL = "http://localhost"

def test_stage_3_flag():
    # Recovered HMAC Secret: checkout2024
    secret = b"checkout2024"
    forged_payload = json.dumps({"order_id": 1001, "status": "PAID", "amount": 9999.00}, separators=(',', ':')).encode()
    signature = hmac.new(secret, forged_payload, hashlib.sha256).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "X-Signature-SHA256": signature
    }
    resp = requests.post(f"{BASE_URL}/api/v1/payment/callback", data=forged_payload, headers=headers, timeout=5)
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("flag") == "SLIIT{c4rt_br34ch_hm4c_51gn4tur3_f0rg3d}"
