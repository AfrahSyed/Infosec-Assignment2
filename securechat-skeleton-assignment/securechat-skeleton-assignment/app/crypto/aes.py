# app/crypto/aes.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def _pad(x: bytes, block_bits: int = 128) -> bytes:
    p = padding.PKCS7(block_bits).padder()
    return p.update(x) + p.finalize()

def _unpad(x: bytes, block_bits: int = 128) -> bytes:
    u = padding.PKCS7(block_bits).unpadder()
    return u.update(x) + u.finalize()

def aes_encrypt_ecb(key16: bytes, plaintext: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key16), modes.ECB()).encryptor()
    return enc.update(_pad(plaintext)) + enc.finalize()

def aes_decrypt_ecb(key16: bytes, ciphertext: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key16), modes.ECB()).decryptor()
    return _unpad(dec.update(ciphertext) + dec.finalize())
