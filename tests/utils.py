from typing import Optional

from sigmon.utils import sha256
from sigmon.sigsum import TreeLeaf

def split(n: int) -> int:
    """
    for n > 1, largest power of two smaller than n
    """

    assert n > 1

    if n & (n-1) == 0:
        k = n >> 1
    else:
        k = 1 << (n.bit_length() - 1)

    return k


def mth(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return sha256(b'')
    elif n == 1:
        return sha256(b'\x00' + leaves[0])

    k = split(n)

    return sha256(
        b'\x01' +
        mth(leaves[0:k]) +
        mth(leaves[k:n])
    )


def inclusion_path(m: int, d: list[bytes]) -> list[bytes]:
    n = len(d)
    assert n > 0

    if n == 1:
        return []

    k = split(n)
    if m < k:
        return inclusion_path(m, d[:k]) + [mth(d[k:])]
    else:
        return inclusion_path(m - k, d[k:]) + [mth(d[:k])]


def consistency_proof(m: int, d: list[bytes]) -> list[bytes]:
    def subproof(m: int, d: list[bytes], b: bool) -> list[bytes]:
        n = len(d)

        if m == n:
            if b:
                return []
            else:
                return [mth(d)]

        k = split(n)
        if m <= k:
            return subproof(m, d[:k], b) + [mth(d[k:])]
        else:
            return subproof(m - k, d[k:], False) + [mth(d[:k])]

    assert 0 < m <= len(d)
    return subproof(m, d, True)


def make_leaf(n: int, key_hash: Optional[bytes] = None) -> TreeLeaf:
    blob = bytes([n]) * 32
    return TreeLeaf(
        checksum=blob,
        signature=blob * 2,
        key_hash=key_hash if key_hash is not None else blob
    )
