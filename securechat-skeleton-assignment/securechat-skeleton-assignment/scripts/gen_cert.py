import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTS = Path("certs")

def load_ca():
    ca_key = serialization.load_pem_private_key((CERTS/"root_ca_key.pem").read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate((CERTS/"root_ca_cert.pem").read_bytes())
    return ca_key, ca_cert

def issue(cn: str, prefix: str):
    ca_key, ca_cert = load_ca()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256()))
    (CERTS/f"{prefix}_key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    (CERTS/f"{prefix}_cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Issued {prefix}_key.pem / {prefix}_cert.pem for CN={cn}")

if __name__ == "__main__":
    cn = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    pref = sys.argv[2] if len(sys.argv) > 2 else "server"
    issue(cn, pref)
