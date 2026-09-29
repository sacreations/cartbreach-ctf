import hmac
import hashlib
import json
import os
from flask import Flask, request, jsonify

app = Flask(__name__)
HMAC_KEY = os.environ.get('HMAC_KEY', 'checkout2024').encode()
STAGE3_FLAG = 'SLIIT{c4rt_br34ch_hm4c_51gn4tur3_f0rg3d}'

def sign_payload(data: bytes) -> str:
    return hmac.new(HMAC_KEY, data, hashlib.sha256).hexdigest()

@app.route('/api/v1/payment/sample', methods=['GET'])
def sample():
    payload = json.dumps({"order_id": 1002, "status": "PENDING", "amount": 149.99}, separators=(',', ':')).encode()
    return jsonify({
        "sample_payload": json.loads(payload),
        "signature": sign_payload(payload),
        "hint": "HMAC-SHA256 signature calculated over raw JSON body bytes"
    })

@app.route('/api/v1/payment/callback', methods=['POST'])
def callback():
    sig = request.headers.get('X-Signature-SHA256', '')
    raw_body = request.get_data()
    expected_sig = sign_payload(raw_body)

    if not hmac.compare_digest(sig, expected_sig):
        return jsonify({"error": "Invalid HMAC signature"}), 403

    try:
        body = json.loads(raw_body)
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400

    # Winning condition: admin order marked as PAID
    if body.get('order_id') == 1001 and body.get('status') == 'PAID':
        return jsonify({
            "message": "Payment verified and processed",
            "order_id": 1001,
            "flag": STAGE3_FLAG
        })

    return jsonify({"message": "Webhook received", "order_id": body.get('order_id')})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
