import base64
import hashlib
import os
import tempfile
import typing

from pathlib import Path

def b64enc(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def b64dec(text: str) -> bytes:
    return base64.b64decode(text)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sync_write(dst: Path, data: bytes) -> None:
    with dst.open('wb') as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def atomic_write(path: Path, data: bytes) -> None:
    path = path.resolve()

    with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, delete=False) as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
        tmp = f.name

    try:
        os.replace(tmp, path)
    except:
        try:
            os.remove(tmp)
        except OSError:
            pass

        raise
