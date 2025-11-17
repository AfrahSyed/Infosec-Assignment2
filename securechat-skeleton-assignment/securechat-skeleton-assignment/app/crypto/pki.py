from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

def verify_cert_with_ca(cert_pem: bytes, ca_pem: bytes, expected_cn: str | None):
    cert = x509.load_pem_x509_certificate(cert_pem)
    ca = x509.load_pem_x509_certificate(ca_pem)

    # 1) CA signature
    ca.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes,
        padding.PKCS1v15(), cert.signature_hash_algorithm
    )

    # 2) Validity window (use UTC-aware properties; fallback for older cryptography)
    now = datetime.now(timezone.utc)
    try:
        not_before = cert.not_valid_before_utc
        not_after  = cert.not_valid_after_utc
    except AttributeError:
        # cryptography < 41 fallback (naive -> make UTC-aware)
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after  = cert.not_valid_after.replace(tzinfo=timezone.utc)

    if not (not_before <= now <= not_after):
        raise ValueError("BAD CERT: expired/not yet valid")

    # 3) Optional CN check
    if expected_cn is not None:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if cn != expected_cn:
            raise ValueError(f"BAD CERT: CN mismatch ({cn} != {expected_cn})")

    return cert
