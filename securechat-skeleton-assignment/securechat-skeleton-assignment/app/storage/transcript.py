# app/storage/transcript.py
import json, hashlib, base64
from pathlib import Path

TRANS_DIR = Path("transcripts")
TRANS_DIR.mkdir(exist_ok=True)

class Transcript:
    def __init__(self, name: str):
        self.path = TRANS_DIR / f"{name}.log"
        self.lines: list[dict] = []

    def append(self, rec: dict):
        self.lines.append(rec)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")

    def fingerprint(self) -> bytes:
        m = hashlib.sha256()
        for rec in self.lines:
            m.update(json.dumps(rec, separators=(",", ":")).encode() + b"\n")
        return m.digest()

    def write_receipt(self, role: str, first_seq: int, last_seq: int, sig: bytes):
        rcpt = {
            "type": "receipt",
            "role": role,
            "first seq": first_seq,
            "last seq": last_seq,
            "transcript sha256": self.fingerprint().hex(),
            "sig": base64.b64encode(sig).decode()
        }
        (TRANS_DIR / f"{role}-receipt.json").write_text(json.dumps(rcpt, indent=2))
        return rcpt
