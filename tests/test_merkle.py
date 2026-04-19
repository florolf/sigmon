from sigmon.monitor import MerkleTree
from sigmon.utils import sha256

import utils

def test_incremental_merkle():
    mt = MerkleTree()

    leaves = []
    for i in range(0, 32):
        leaf = i.to_bytes(length=4)

        mt.add_leaf(sha256(b'\x00' + leaf))
        leaves.append(leaf)

        assert utils.mth(leaves) == mt.root_hash()
