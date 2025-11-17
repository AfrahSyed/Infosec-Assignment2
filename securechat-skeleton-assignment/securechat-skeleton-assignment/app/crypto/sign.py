# app/crypto/sign.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

def rsa_sign_sha256(priv_pem: bytes, data: bytes) -> bytes:
    key = serialization.load_pem_private_key(priv_pem, password=None)
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())

def rsa_verify_sha256(cert_pem: bytes, data: bytes, sig: bytes) -> None:
    cert = x509.load_pem_x509_certificate(cert_pem)
    cert.public_key().verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
