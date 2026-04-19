import dataclasses
from typing import Optional

import nacl.signing

from sigmon.sigsum import (
    ConsistencyProof,
    Cosignature,
    InclusionProof,
    SigsumKey,
    SigsumLogAPI,
    TreeHead,
    TreeLeaf,
)
from sigmon.utils import b64enc, sha256

import utils

class FakeWitness:
    def __init__(self, name: str):
        seed = sha256(("witness\x00" + name).encode())

        self.name = name
        self.key = nacl.signing.SigningKey(seed)
        self.key_hash = sha256(bytes(self.key.verify_key))
        self.time = 0
        self.active = True

    def cosign(self, origin: str, size: int, root: bytes) -> Optional[Cosignature]:
        if not self.active:
            return None

        commitment = f'cosignature/v1\ntime {self.time}\n{origin}\n{size}\n{b64enc(root)}\n'
        sig = self.key.sign(commitment.encode()).signature

        return Cosignature(
            key_hash=self.key_hash,
            timestamp=self.time,
            signature=sig,
        )

    def policy_line(self) -> str:
        return f'witness {self.name} {bytes(self.key.verify_key).hex()}'


class FakeSigsumLog(SigsumLogAPI):
    def __init__(self, name: str):
        seed = sha256(("log\x00" + name).encode())

        self.name = name
        self.key = nacl.signing.SigningKey(seed)
        self.pubkey = SigsumKey(bytes(self.key.verify_key))
        self.endpoint = f'http://{name}.example.com'
        self.leaves: list[TreeLeaf] = []
        self.witnesses: list[FakeWitness] = []

    def append(self, leaf: TreeLeaf) -> int:
        idx = len(self.leaves)
        self.leaves.append(leaf)
        return idx

    def add_witness(self, w: FakeWitness) -> None:
        self.witnesses.append(w)

    def policy_line(self) -> str:
        return f'log {self.name} {bytes(self.pubkey.key).hex()}'

    def _raw_leaves(self, n: Optional[int] = None) -> list[bytes]:
        if n is None:
            n = len(self.leaves)

        return [l.serialize() for l in self.leaves[:n]]

    def get_tree_head(self) -> TreeHead:
        origin = f'sigsum.org/v1/tree/{self.pubkey.key_hash.hex()}'
        size = len(self.leaves)
        root = utils.mth(self._raw_leaves())

        cosigs = []
        for w in self.witnesses:
            cs = w.cosign(origin, size, root)

            if cs is not None:
                cosigs.append(cs)

        th = TreeHead(
            origin=origin,
            signature=b'',
            size=size,
            root_hash=root,
            cosignatures=cosigs,
        )

        signature = self.key.sign(th.commitment().encode()).signature
        return dataclasses.replace(th, signature=signature)

    def get_leaves(self, start: int, end: int) -> list[TreeLeaf]:
        return list(self.leaves[start:end])

    def get_inclusion_proof(self, size: int, leaf: TreeLeaf) -> InclusionProof:
        if size <= 1:
            raise ValueError(f'size ({size}) must be larger than 1')

        index = self.leaves.index(leaf)
        if index >= size:
            raise ValueError(f'leaf index {index} is past specified tree size {size}')

        return InclusionProof(
            leaf_index=index,
            node_hashes=utils.inclusion_path(index, self._raw_leaves(size)),
        )

    def get_consistency_proof(self, old_size: int, new_size: int) -> ConsistencyProof:
        if old_size == 0 or old_size == new_size:
            raise ValueError(f'invalid arguments old_size={old_size} new_size={new_size}')

        return ConsistencyProof(
            utils.consistency_proof(old_size, self._raw_leaves()),
            old_size,
            new_size,
        )
