import base64
import hashlib

def b64enc(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def b64dec(text: str) -> bytes:
    return base64.b64decode(text)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
