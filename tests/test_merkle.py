from sigmon.monitor import MerkleTree
from sigmon.utils import sha256

def mth(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return sha256(b'')
    elif n == 1:
        return sha256(b'\x00' + leaves[0])

    if n & (n-1) == 0:
        k = n >> 1
    else:
        k = 1 << (n.bit_length() - 1)

    return sha256(
        b'\x01' +
        mth(leaves[0:k]) +
        mth(leaves[k:n])
    )

def test_incremental_merkle():
    mt = MerkleTree()

    leaves = []
    for i in range(0, 32):
        leaf = i.to_bytes(length=4)

        mt.add_leaf(sha256(b'\x00' + leaf))
        leaves.append(leaf)

        assert mth(leaves) == mt.root_hash()
