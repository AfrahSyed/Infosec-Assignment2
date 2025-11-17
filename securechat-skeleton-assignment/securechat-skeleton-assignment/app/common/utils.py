# app/common/utils.py
import base64, hashlib, time

def now_ms() -> int:
    return int(time.time() * 1000)

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())

def signable_digest(seqno: int, ts_ms: int, ct_b64: str) -> bytes:
    # digest over seq||ts||ct (as specified)
    m = hashlib.sha256()
    m.update(seqno.to_bytes(8, "big"))
    m.update(ts_ms.to_bytes(8, "big"))
    m.update(ct_b64.encode())
    return m.digest()
