# scripts/replay_once.py
import argparse, json, os, socket, hashlib
from pathlib import Path
from app.common.protocol import send_json, recv_json, T_HELLO, T_SRV_HELLO, T_DH_CLIENT, T_DH_SERVER, T_AUTH_BLOB, T_AUTH_OK, T_MSG, T_CLOSE
from app.common.utils import b64e, b64d, now_ms, signable_digest
from app.crypto.aes import aes_encrypt_ecb, aes_decrypt_ecb
from app.crypto.dh import DEFAULT_PARAMS, make_keypair, derive_key, DHParams
from app.crypto.pki import verify_cert_with_ca
from app.crypto.sign import rsa_sign_sha256

CERTS = Path("certs")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--server-cn", default="localhost")
    ap.add_argument("--text", default="test")
    args = ap.parse_args()

    ca_pem = (CERTS/"root_ca_cert.pem").read_bytes()
    me_cert_pem = (CERTS/"client_cert.pem").read_bytes()
    me_key_pem  = (CERTS/"client_key.pem").read_bytes()

    s = socket.create_connection((args.host, args.port))

    # hello <-> server hello
    nonce = os.urandom(16)
    send_json(s, {"type": T_HELLO, "client cert": me_cert_pem.decode(), "nonce": b64e(nonce)})
    sh = recv_json(s); assert sh["type"] == T_SRV_HELLO
    srv_cert_pem = sh["server cert"].encode()
    verify_cert_with_ca(srv_cert_pem, ca_pem, expected_cn=args.server_cn)

    # temp DH for credentials
    a, A = make_keypair(DEFAULT_PARAMS)
    send_json(s, {"type": T_DH_CLIENT, "g": DEFAULT_PARAMS.g, "p": DEFAULT_PARAMS.p, "A": A})
    r = recv_json(s); assert r["type"] == T_DH_SERVER
    Ktmp = derive_key(DEFAULT_PARAMS, a, r["B"])
    payload = {"type":"login","email":args.email,"pwd":b64e(args.password.encode())}
    ct = aes_encrypt_ecb(Ktmp, json.dumps(payload).encode())
    send_json(s, {"type": T_AUTH_BLOB, "ct": b64e(ct)})
    ok = recv_json(s); assert ok["type"] == T_AUTH_OK

    # post-auth DH -> session key
    a2, A2 = make_keypair(DEFAULT_PARAMS)
    send_json(s, {"type": T_DH_CLIENT, "g": DEFAULT_PARAMS.g, "p": DEFAULT_PARAMS.p, "A": A2})
    r2 = recv_json(s); assert r2["type"] == T_DH_SERVER
    K = derive_key(DEFAULT_PARAMS, a2, r2["B"])

    # build first message
    seq = 1
    ts = now_ms()
    ct_b64 = b64e(aes_encrypt_ecb(K, args.text.encode()))
    h = signable_digest(seq, ts, ct_b64)
    sig_b64 = b64e(rsa_sign_sha256(me_key_pem, h))
    msg = {"type": T_MSG, "seqno": seq, "ts": ts, "ct": ct_b64, "sig": sig_b64}

    # send once (should echo)
    send_json(s, msg)
    print("echo:", recv_json(s))

    # send exact same message again (same seqno) -> expect REPLAY
    send_json(s, msg)
    print("second send result:", recv_json(s))  # {'type': 'REPLAY'} expected

    send_json(s, {"type": T_CLOSE})
    s.close()

if __name__ == "__main__":
    main()
