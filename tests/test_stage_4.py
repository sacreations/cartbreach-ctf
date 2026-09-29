"""Stage 4: FORENSIC-01 — The Orphaned Ledger (Database Dump & Hash Cracking)."""
import gzip
import io
import requests

BASE_URL = "http://localhost"

def test_stage_4_flag():
    # Download static database dump
    resp = requests.get(f"{BASE_URL}/static/backups/storefront_backup.sql.gz", timeout=5)
    assert resp.status_code == 200

    # Decompress SQL archive
    with gzip.GzipFile(fileobj=io.BytesIO(resp.content)) as gz:
        sql_text = gz.read().decode('utf-8')

    # Flag embedded inside the forensic dump
    assert "SLIIT{c4rt_br34ch_f0r3n51c_db_dump}" in sql_text
    assert "cb_internal_svc_t0k3n_4dm1n" in sql_text
