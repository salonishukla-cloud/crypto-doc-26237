#!/usr/bin/env python3
"""
Cryptographic Attribution Platform — Mock REST API Server
=========================================================
Simulates the Rust backend over HTTP for the web UI.
Runs on port 8081. Zero external dependencies (stdlib only).

Usage:
  cd integration/ui
  python api_server.py

Endpoints:
  GET  /api/health
  GET  /api/ledger/blocks
  GET  /api/nodes/status
  POST /api/encrypt      { document_id, recipients, filename?, size? }
  POST /api/decrypt      { recipient_id, session_id, document_id }
  POST /api/forensics    { source, document_id, filename?, size? }
"""

import json
import uuid
import datetime
import random
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

# ── Config ─────────────────────────────────────────────────────────────
PORT = 8081

# ── Helpers ─────────────────────────────────────────────────────────────
def rand_hex(n: int) -> str:
    return ''.join(random.choices('0123456789abcdef', k=n))

def rand_uuid() -> str:
    return str(uuid.uuid4())

def now_iso() -> str:
    return datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

# ── In-memory mock ledger (grows with decrypt calls) ────────────────────
BLOCKS = [
    {
        "height": 0,
        "block_hash": f"00a89f{rand_hex(56)}88b2",
        "prev_hash": "0" * 64,
        "merkle_root": rand_hex(64),
        "validator": "network-genesis",
        "timestamp": "2026-01-01T00:00:00Z",
        "tx_count": 1,
    },
    {
        "height": 1,
        "block_hash": rand_hex(64),
        "prev_hash": f"00a89f{rand_hex(56)}88b2",
        "merkle_root": rand_hex(64),
        "validator": "node-1",
        "timestamp": "2026-09-01T08:15:22Z",
        "tx_count": 3,
    },
    {
        "height": 2,
        "block_hash": rand_hex(64),
        "prev_hash": rand_hex(64),
        "merkle_root": rand_hex(64),
        "validator": "node-3",
        "timestamp": "2026-09-28T22:41:05Z",
        "tx_count": 1,
    },
]

# ── Request Handler ──────────────────────────────────────────────────────
class APIHandler(BaseHTTPRequestHandler):
    server_version = "CryptoAttributionAPI/0.1"

    def log_message(self, fmt, *args):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        print(f"  [{ts}]  {self.command:6s}  {self.path}  —  {fmt % args}")

    # ── CORS ──────────────────────────────────────────────────────────
    def add_cors(self):
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(204)
        self.add_cors()
        self.end_headers()

    # ── JSON response helper ───────────────────────────────────────────
    def json_response(self, data, code: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.add_cors()
        self.send_header("Content-Type",   "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── Read request JSON body ─────────────────────────────────────────
    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return {}

    # ── GET ────────────────────────────────────────────────────────────
    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/health":
            self.json_response({
                "status":       "online",
                "platform":     "Cryptographic Attribution & Immutable Provenance Platform",
                "version":      "0.1.0-postquantum",
                "nodes":        4,
                "chain_height": len(BLOCKS) - 1,
                "timestamp":    now_iso(),
                "modules": {
                    "encryption": "AES-256-GCM + ML-KEM-768 (FIPS 203)",
                    "watermark":  "142-bit 4-Channel Invisible Forensic Watermark",
                    "pqcrypto":   "ML-DSA-65 (FIPS 204) + RFC 8785 Canonical JSON",
                    "ledger":     "4-Node Permissioned Append-Only DLT",
                }
            })

        elif path == "/api/ledger/blocks":
            self.json_response({
                "blocks":      BLOCKS,
                "total":       len(BLOCKS),
                "chain_valid": True,
                "chain_height": len(BLOCKS) - 1,
            })

        elif path == "/api/nodes/status":
            h = len(BLOCKS) - 1
            self.json_response({
                "nodes": [
                    {"id": 1, "role": "Key Custody & Validator", "port": 8001,
                     "height": h, "online": True, "latency_ms": 0},
                    {"id": 2, "role": "Verification Enclave",    "port": 8002,
                     "height": h, "online": True, "latency_ms": 0},
                    {"id": 3, "role": "Attribution Analysis",    "port": 8003,
                     "height": h, "online": True, "latency_ms": 0},
                    {"id": 4, "role": "Offline Audit Store",     "port": 8004,
                     "height": h, "online": True, "latency_ms": 0},
                ]
            })

        else:
            self.json_response({"error": "Not Found"}, 404)

    # ── POST ───────────────────────────────────────────────────────────
    def do_POST(self):
        path = urlparse(self.path).path
        body = self.read_json()

        if path == "/api/encrypt":
            doc_id     = body.get("document_id", "DOC-UNKNOWN")
            recipients = body.get("recipients",   [])
            filename   = body.get("filename",     None)
            size_bytes = body.get("size",         0)

            payload_bytes = random.randint(50_000, 500_000)
            nonce_hex     = rand_hex(24)
            auth_tag      = rand_hex(32)
            sha256        = rand_hex(64)

            envelopes = [
                {
                    "recipient_id":              r,
                    "kem_algorithm":             "ML-KEM-768",
                    "kem_ciphertext_bytes":      1088,
                    "kem_ciphertext_preview":    rand_hex(16) + "…[1088 bytes encapsulation]",
                    "encrypted_dek_tag":         rand_hex(16),
                }
                for r in recipients
            ]

            resp = {
                "status": "success",
                "package": {
                    "magic":               "CRPTDOC1",
                    "version":             "1.0.0",
                    "document_id":         doc_id,
                    "created_at":          now_iso(),
                    "cipher":              "AES-256-GCM",
                    "kem":                 "ML-KEM-768",
                    "nonce_hex":           nonce_hex,
                    "auth_tag_hex":        auth_tag,
                    "payload_sha256":      sha256,
                    "payload_bytes":       payload_bytes,
                    "source_filename":     filename,
                    "source_size_bytes":   size_bytes or payload_bytes,
                    "recipient_envelopes": envelopes,
                    "envelope_count":      len(envelopes),
                }
            }
            self.json_response(resp)

        elif path == "/api/decrypt":
            recipient_id = body.get("recipient_id", "UNKNOWN")
            session_id   = body.get("session_id",   rand_uuid())
            doc_id       = body.get("document_id",  "DOC-UNKNOWN")

            event_id    = "evt-" + rand_hex(16)
            wm_id       = "wm-"  + rand_hex(8)
            wm_hash     = rand_hex(64)
            block_height = len(BLOCKS)
            block_hash   = rand_hex(64)
            prev_hash    = BLOCKS[-1]["block_hash"]
            validator    = f"node-{random.randint(1, 4)}"

            # Append new block to in-memory ledger
            BLOCKS.append({
                "height":      block_height,
                "block_hash":  block_hash,
                "prev_hash":   prev_hash,
                "merkle_root": rand_hex(64),
                "validator":   validator,
                "timestamp":   now_iso(),
                "tx_count":    1,
                "event_id":    event_id,
            })

            resp = {
                "status": "success",
                "pipeline": {
                    "step_1_decryption": {
                        "status": "OK",
                        "module": "Module 1 — ML-KEM-768 Decapsulation + AES-256-GCM Decryption",
                        "latency_ms": random.randint(10, 25),
                    },
                    "step_2_watermark": {
                        "status": "OK",
                        "module": "Module 2 — 142-bit Invisible Multi-Layer Watermark Embedded",
                        "latency_ms": random.randint(30, 60),
                    },
                    "step_3_signing": {
                        "status": "OK",
                        "module": "Module 3 — Canonical RFC 8785 JSON + ML-DSA-65 FIPS 204 Signature",
                        "latency_ms": random.randint(80, 120),
                    },
                    "step_4_ledger": {
                        "status": "OK",
                        "module": f"Module 4 — Committed on 4-Node Ledger at Block #{block_height}",
                        "latency_ms": random.randint(5, 12),
                    },
                },
                "event": {
                    "event_id":              event_id,
                    "document_id":           doc_id,
                    "recipient_id":          recipient_id,
                    "session_id":            session_id,
                    "watermark_id":          wm_id,
                    "timestamp":             now_iso(),
                    "watermark_hash":        wm_hash,
                    "signature_algorithm":   "ML-DSA-65",
                    "public_key_fingerprint": rand_hex(64),
                    "signature":             rand_hex(16) + "…[3309 bytes FIPS 204 ML-DSA-65]",
                },
                "ledger_receipt": {
                    "event_id":      event_id,
                    "block_height":  block_height,
                    "block_hash":    block_hash,
                    "prev_hash":     prev_hash,
                    "merkle_proof":  [rand_hex(64), rand_hex(64)],
                    "validator":     validator,
                    "committed_at":  now_iso(),
                },
            }
            self.json_response(resp)

        elif path == "/api/forensics":
            source   = body.get("source",      "unknown")
            doc_id   = body.get("document_id", "DOC-UNKNOWN")
            filename = body.get("filename",    None)

            now = now_iso()

            if source == "valid":
                resp = {
                    "status":     "success",
                    "verdict":    "CONFIRMED_ATTRIBUTION",
                    "confidence": 100.0,
                    "attribution": {
                        "recipient_id": "officer.shukla@hq.defence.gov",
                        "session_id":   "SESS-AIRGAP-8891",
                        "document_id":  doc_id,
                    },
                    "watermark": {
                        "extracted":      True,
                        "watermark_id":   f"wm-shukla-{rand_hex(6)}",
                        "watermark_hash": rand_hex(64),
                        "ledger_match":   True,
                        "channels": [
                            "ZeroWidthUnicode",
                            "HomoglyphSubstitution",
                            "XMP",
                            "SpectrumSteganography",
                        ],
                    },
                    "signature": {
                        "algorithm":             "ML-DSA-65",
                        "valid":                 True,
                        "public_key_fingerprint": rand_hex(64),
                        "non_repudiation":       "AFFIRMED",
                    },
                    "ledger": {
                        "found":         True,
                        "block_height":  len(BLOCKS) - 1,
                        "block_hash":    BLOCKS[-1]["block_hash"],
                        "merkle_valid":  True,
                        "chain_valid":   True,
                    },
                    "source_filename": filename,
                    "generated_at":    now,
                }
            elif source == "tampered":
                resp = {
                    "status":     "success",
                    "verdict":    "TAMPERING_DETECTED",
                    "confidence": 0.0,
                    "watermark": {"extracted": True,  "ledger_match": False},
                    "signature": {"algorithm": "ML-DSA-65", "valid": False, "non_repudiation": "FAILED"},
                    "ledger":    {"found": False},
                    "source_filename": filename,
                    "generated_at": now,
                }
            else:
                resp = {
                    "status":     "success",
                    "verdict":    "UNATTRIBUTED",
                    "confidence": 0.0,
                    "watermark": {"extracted": False},
                    "signature": {"valid": False},
                    "ledger":    {"found": False},
                    "source_filename": filename,
                    "generated_at": now,
                }

            self.json_response(resp)

        else:
            self.json_response({"error": "Endpoint not found"}, 404)


# ── Main ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass

    try:
        httpd = HTTPServer(("localhost", PORT), APIHandler)
    except OSError as e:
        print(f"\n  [!] Could not bind to port {PORT}: {e}")
        print(f"      Is another process already using port {PORT}?\n")
        sys.exit(1)

    banner = f"""
====================================================================
  Cryptographic Attribution Platform -- Mock REST API Server
  Listening on  ->  http://localhost:{PORT}

  Endpoints:
    GET  /api/health
    GET  /api/ledger/blocks
    GET  /api/nodes/status
    POST /api/encrypt
    POST /api/decrypt
    POST /api/forensics
====================================================================
"""
    print(banner)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down API server...")
        httpd.shutdown()
