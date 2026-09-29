from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import os
import subprocess

app = FastAPI(title="CartBreach Internal Inventory API")

INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "cb_internal_svc_t0k3n_4dm1n")

class ExportRequest(BaseModel):
    template_name: str
    order_id: int = 1001

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/api/v1/admin/export")
def export_invoice(req: ExportRequest, x_internal_token: str = Header(None)):
    if x_internal_token != INTERNAL_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid internal service token")

    # ponytail: intentional command injection — unsanitized template_name concatenated to shell (Stage 5)
    cmd = f"echo 'Rendering template {req.template_name}'"
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        return {"status": "success", "output": output.decode('utf-8', errors='ignore')}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "output": e.output.decode('utf-8', errors='ignore')}
    except Exception as e:
        return {"status": "error", "detail": str(e)}
