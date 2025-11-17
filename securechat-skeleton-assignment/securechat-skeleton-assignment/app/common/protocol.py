# app/common/protocol.py
import json
import socket

# ---- Message type tags ----
T_HELLO       = "hello"
T_SRV_HELLO   = "server hello"
T_DH_CLIENT   = "dh client"
T_DH_SERVER   = "dh server"
T_AUTH_BLOB   = "auth_blob"
T_AUTH_OK     = "auth_ok"
T_AUTH_ERR    = "auth_err"
T_MSG         = "msg"
T_ERR         = "ERR"
T_REPLAY      = "REPLAY"
T_SIG_FAIL    = "SIG FAIL"
T_DEC_FAIL    = "DEC FAIL"
T_CLOSE       = "close"
T_RECEIPT     = "receipt"

# ---- newline-delimited JSON framing ----
def send_json(sock: socket.socket, obj: dict) -> None:
    sock.sendall(json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode() + b"\n")

def recv_json(sock: socket.socket) -> dict:
    buf = bytearray()
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("peer closed")
        if ch == b"\n":
            break
        buf += ch
    return json.loads(buf.decode())
