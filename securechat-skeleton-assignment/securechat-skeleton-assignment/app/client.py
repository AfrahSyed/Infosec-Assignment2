# app/client.py
import argparse, json, os, socket, hashlib, threading
from pathlib import Path
from app.common.protocol import (
    T_HELLO, T_SRV_HELLO, T_DH_CLIENT, T_DH_SERVER, T_AUTH_BLOB, T_AUTH_OK, T_AUTH_ERR,
    T_MSG, T_CLOSE, send_json, recv_json
)
from app.common.utils import b64e, b64d, now_ms, signable_digest
from app.crypto.aes import aes_encrypt_ecb, aes_decrypt_ecb
from app.crypto.dh import DEFAULT_PARAMS, make_keypair, derive_key
from app.crypto.pki import verify_cert_with_ca
from app.crypto.sign import rsa_sign_sha256, rsa_verify_sha256
from app.storage.transcript import Transcript

CERTS = Path("certs")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--server-cn", default="localhost")
    args = ap.parse_args()

    ca_pem = (CERTS/"root_ca_cert.pem").read_bytes()
    me_cert_pem = (CERTS/"client_cert.pem").read_bytes()
    me_key_pem  = (CERTS/"client_key.pem").read_bytes()

    s = socket.create_connection((args.host, args.port))

    # 1) hello -> server hello (+ verify server cert)
    send_json(s, {"type": T_HELLO})
    sh = recv_json(s)
    assert sh["type"] == T_SRV_HELLO
    srv_cert_pem = b64d(sh["server cert"])  # Fixed: decode base64
    verify_cert_with_ca(srv_cert_pem, ca_pem, expected_cn=args.server_cn)

    # 2) DH key exchange
    cli_priv, cli_pub = make_keypair(DEFAULT_PARAMS)
    send_json(s, {"type": T_DH_CLIENT, "pub": str(cli_pub)})  # Fixed: use "pub"
    dh_srv = recv_json(s)
    assert dh_srv["type"] == T_DH_SERVER
    srv_pub = int(dh_srv["pub"])  # Fixed: use "pub"
    K = derive_key(DEFAULT_PARAMS, cli_priv, srv_pub)

    # 3) Authentication
    auth_data = {
        "email": args.email,
        "password": args.password,
        "cert": b64e(me_cert_pem)
    }
    auth_json = json.dumps(auth_data).encode()
    ct = aes_encrypt_ecb(K, auth_json)
    send_json(s, {"type": T_AUTH_BLOB, "blob": b64e(ct)})
    
    auth_resp = recv_json(s)
    if auth_resp.get("type") != T_AUTH_OK:
        raise SystemExit(f"Auth failed: {auth_resp}")
    
    print("Authentication successful!")

    # 4) Bidirectional chat
    tr = Transcript("client")
    peer_fp = hashlib.sha256(srv_cert_pem).hexdigest()
    seq_client = 0
    last_seq_server = 0
    active = True

    print("Connected. Type messages; 'exit' to quit.\n")

    def receive_loop():
        nonlocal last_seq_server, active
        s.settimeout(0.5)
        while active:
            try:
                m = recv_json(s)
                
                if m["type"] == T_CLOSE:
                    print("\n[Server disconnected]")
                    active = False
                    break
                    
                if m["type"] != T_MSG:
                    continue

                if not (m["seqno"] > last_seq_server):
                    print("[Replay detected]")
                    continue
                last_seq_server = m["seqno"]

                try:
                    hdig = signable_digest(m["seqno"], m["ts"], m["ct"])
                    rsa_verify_sha256(srv_cert_pem, hdig, b64d(m["sig"]))
                except Exception:
                    print("[Signature verification failed]")
                    continue

                try:
                    pt = aes_decrypt_ecb(K, b64d(m["ct"]))
                    print(f"\r[SERVER] {pt.decode()}\n> ", end="", flush=True)
                except Exception:
                    print("[Decryption failed]")
                    continue

                tr.append({**m, "peer": peer_fp})

            except socket.timeout:
                continue
            except Exception:
                active = False
                break

    # Start receive thread
    recv_thread = threading.Thread(target=receive_loop, daemon=True)
    recv_thread.start()

    # Send loop (main thread)
    while active:
        try:
            print("> ", end="", flush=True)
            line = input().strip()
            
            if line.lower() in {"exit", "quit"}:
                send_json(s, {"type": T_CLOSE})
                active = False
                break
            
            if line:
                seq_client += 1
                ts = now_ms()
                ct = aes_encrypt_ecb(K, line.encode())
                ct_b64 = b64e(ct)
                h = signable_digest(seq_client, ts, ct_b64)
                sig = b64e(rsa_sign_sha256(me_key_pem, h))
                
                msg = {
                    "type": T_MSG,
                    "seqno": seq_client,
                    "ts": ts,
                    "ct": ct_b64,
                    "sig": sig
                }
                send_json(s, msg)
                tr.append({**msg, "peer": peer_fp})
                
        except (EOFError, KeyboardInterrupt):
            active = False
            break

    recv_thread.join(timeout=1)

    # 5) teardown: sign transcript
    sig = rsa_sign_sha256(me_key_pem, tr.fingerprint())
    tr.write_receipt("client", 1, last_seq_server + seq_client, sig)
    s.close()
    print("\n[Connection closed]")

if __name__ == "__main__":
    main()