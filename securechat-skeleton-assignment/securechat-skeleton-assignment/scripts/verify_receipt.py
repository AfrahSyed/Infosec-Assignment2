import json, sys, hashlib, base64
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def main(transcript_path, receipt_path, peer_cert_path):
    lines = Path(transcript_path).read_text(encoding="utf-8").splitlines()
    m = hashlib.sha256()
    for line in lines:
        m.update((line + "\n").encode())
    digest = m.digest().hex()

    receipt = json.loads(Path(receipt_path).read_text())
    assert receipt["transcript sha256"] == digest, "Transcript digest mismatch"

    cert = x509.load_pem_x509_certificate(Path(peer_cert_path).read_bytes())
    sig = base64.b64decode(receipt["sig"])
    cert.public_key().verify(sig, bytes.fromhex(digest), padding.PKCS1v15(), hashes.SHA256())
    print("OK: receipt verifies and matches transcript")

if __name__ == "__main__":
    main(*sys.argv[1:4])
