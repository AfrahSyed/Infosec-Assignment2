# app/server.py
import argparse
import json
import socket
import threading
import hashlib
import base64
from pathlib import Path
from app.common.protocol import (
    T_HELLO, T_SRV_HELLO, T_DH_CLIENT, T_DH_SERVER, T_AUTH_BLOB, T_AUTH_OK, T_AUTH_ERR,
    T_MSG, T_ERR, T_REPLAY, T_SIG_FAIL, T_DEC_FAIL, T_CLOSE,
    send_json, recv_json
)
from app.common.utils import b64e, b64d, now_ms, signable_digest
from app.crypto.aes import aes_encrypt_ecb, aes_decrypt_ecb
from app.crypto.dh import DHParams, DEFAULT_PARAMS, make_keypair, derive_key
from app.crypto.pki import verify_cert_with_ca
from app.crypto.sign import rsa_sign_sha256, rsa_verify_sha256
from app.storage.db import create_user, auth_user
from app.storage.transcript import Transcript

CERTS = Path("certs")

def handle_client(conn, addr):
    client_cert_pem = None
    K = None
    srv_key_pem = None
    tr = None
    
    try:
        print(f"[Connection from {addr}]")
        ca_pem = (CERTS / "root_ca_cert.pem").read_bytes()
        srv_cert_pem = (CERTS / "server_cert.pem").read_bytes()
        srv_key_pem = (CERTS / "server_key.pem").read_bytes()

        # 1) HELLO exchange
        print("[Waiting for HELLO...]")
        hello = recv_json(conn)
        assert hello["type"] == T_HELLO, "Expected HELLO"
        print("[Received HELLO]")
        
        send_json(conn, {
            "type": T_SRV_HELLO,
            "server cert": b64e(srv_cert_pem)
        })
        print("[Sent SRV_HELLO]")

        # 2) DH key exchange
        dh_params = DEFAULT_PARAMS
        srv_priv, srv_pub = make_keypair(dh_params)
        
        print("[Waiting for DH_CLIENT...]")
        dh_client = recv_json(conn)
        assert dh_client["type"] == T_DH_CLIENT, "Expected DH_CLIENT"
        client_pub = int(dh_client["pub"])
        print("[Received DH_CLIENT]")
        
        send_json(conn, {
            "type": T_DH_SERVER,
            "pub": str(srv_pub)
        })
        print("[Sent DH_SERVER]")
        
        # Derive shared key
        K = derive_key(dh_params, srv_priv, client_pub)
        print("[Shared key derived]")

        # 3) Authentication
        print("[Waiting for AUTH_BLOB...]")
        auth_blob = recv_json(conn)
        assert auth_blob["type"] == T_AUTH_BLOB, "Expected AUTH_BLOB"
        print("[Received AUTH_BLOB]")
        
        # Decrypt the auth blob
        try:
            decrypted = aes_decrypt_ecb(K, b64d(auth_blob["blob"]))
            auth_data = json.loads(decrypted.decode())
            print(f"[Decrypted auth data for: {auth_data.get('email', 'unknown')}]")
        except Exception as e:
            print(f"[Decryption error: {e}]")
            send_json(conn, {"type": T_AUTH_ERR, "why": "Decryption failed"})
            return
        
        email = auth_data["email"]
        password = auth_data["password"]
        client_cert_pem = b64d(auth_data["cert"])
        
        # Verify client certificate with CA
        print("[Verifying client cert...]")
        try:
            verify_cert_with_ca(client_cert_pem, ca_pem, expected_cn=None)
            print("[Client cert verified]")
        except Exception as e:
            print(f"[Cert verification failed: {e}]")
            send_json(conn, {"type": T_AUTH_ERR, "why": f"Certificate verification failed: {e}"})
            return
        
        # Authenticate or create user
        print(f"[Authenticating {email}...]")
        if not auth_user(email, password):
            print(f"[Creating new user {email}...]")
            if not create_user(email, password):
                print("[Auth/create failed]")
                send_json(conn, {"type": T_AUTH_ERR, "why": "Authentication failed"})
                return
        
        send_json(conn, {"type": T_AUTH_OK})
        print("[Sent AUTH_OK - Authentication complete]\n")

        # 4) Bidirectional chat with threading
        tr = Transcript("server")
        peer_fp = hashlib.sha256(client_cert_pem).hexdigest()
        last_seq_client = 0
        seq_server = 0
        active = True

        print(f"[Connected to {addr}] Chat started. Type messages or 'exit' to close.\n")

        def receive_loop():
            nonlocal last_seq_client, active
            conn.settimeout(0.5)
            while active:
                try:
                    m = recv_json(conn)
                    
                    if m["type"] == T_CLOSE:
                        print("\n[Client disconnected]")
                        active = False
                        break
                        
                    if m["type"] != T_MSG:
                        continue

                    if not (m["seqno"] > last_seq_client):
                        send_json(conn, {"type": T_REPLAY})
                        continue
                    last_seq_client = m["seqno"]

                    try:
                        hdig = signable_digest(m["seqno"], m["ts"], m["ct"])
                        rsa_verify_sha256(client_cert_pem, hdig, b64d(m["sig"]))
                    except Exception:
                        send_json(conn, {"type": T_SIG_FAIL})
                        continue

                    try:
                        pt = aes_decrypt_ecb(K, b64d(m["ct"]))
                        print(f"\r[CLIENT] {pt.decode()}\n> ", end="", flush=True)
                    except Exception:
                        send_json(conn, {"type": T_DEC_FAIL})
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
                server_msg = input().strip()
                
                if server_msg.lower() in {"exit", "quit"}:
                    send_json(conn, {"type": T_CLOSE})
                    active = False
                    break
                
                if server_msg:
                    seq_server += 1
                    ts = now_ms()
                    ct = aes_encrypt_ecb(K, server_msg.encode())
                    ct_b64 = b64e(ct)
                    h = signable_digest(seq_server, ts, ct_b64)
                    sig = b64e(rsa_sign_sha256(srv_key_pem, h))
                    
                    msg_to_send = {
                        "type": T_MSG,
                        "seqno": seq_server,
                        "ts": ts,
                        "ct": ct_b64,
                        "sig": sig
                    }
                    send_json(conn, msg_to_send)
                    tr.append({**msg_to_send, "peer": peer_fp})
                    
            except (EOFError, KeyboardInterrupt):
                active = False
                break

        recv_thread.join(timeout=1)

        # 5) teardown: sign transcript
        if client_cert_pem and srv_key_pem and tr:
            print("\n[Signing transcript...]")
            sig = rsa_sign_sha256(srv_key_pem, tr.fingerprint())
            tr.write_receipt("server", 1, last_seq_client + seq_server, sig)
            print("[Transcript saved]")

    except Exception as e:
        print(f"[Error in handle_client: {e}]")
        import traceback
        traceback.print_exc()
        try:
            send_json(conn, {"type": T_ERR, "why": str(e)})
        except Exception:
            pass
    finally:
        conn.close()
        print(f"[Connection closed: {addr}]")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(5)
    print(f"Server listening on {args.host}:{args.port}")

    while True:
        try:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[Server shutting down]")
            break


if __name__ == "__main__":
    main()