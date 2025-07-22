#!/usr/bin/env python3

import logging
import copy
from typing import Optional, Self, Any

from .sigsum import SigsumLogAPI, TreeLeaf
from .utils import sha256

logger = logging.getLogger(__name__)

class MerkleTree:
    "Incremental Merkle tree computation as per RFC9162 Section 2.1.2"

    size: int
    stack: list[bytes]

    def __init__(self, size: Optional[int] = None, stack: Optional[list[bytes]] = None):
        if size is None and stack is None:
            self.size = 0
            self.stack = []
        elif size is not None and stack is not None:
            self.size = size
            self.stack = stack
        else:
            raise ValueError("both or none of size and stack must be given")

    def add_leaf(self, leaf_hash: bytes):
        self.stack.append(leaf_hash)

        index = self.size

        merge_count = 0
        while index & 1 == 1:
            merge_count += 1
            index >>= 1

        for _ in range(0, merge_count):
            right = self.stack.pop()
            left = self.stack.pop()

            self.stack.append(sha256(b'\x01' + left + right))

        self.size += 1

    def root_hash(self):
        assert self.size > 0

        stack = self.stack.copy()

        while len(stack) > 1:
            right = stack.pop()
            left = stack.pop()

            stack.append(sha256(b'\x01' + left + right))

        return stack[0]


class Monitor:
    def __init__(self, log: SigsumLogAPI, tree: MerkleTree):
        self.log = log
        self.tree = tree

    @classmethod
    def from_log(cls, log: SigsumLogAPI, start_index: Optional[int] = None) -> Self:
        if start_index == 0:
            return cls(log, MerkleTree(0, []))

        th = log.get_tree_head()

        tail = False
        if start_index is None:
            start_index = th.size - 1
            tail = True

        # The inclusion proof of the last entry of the log for a given tree
        # size is the sequence of left siblings on the path up to the root.
        # This is exactly what the "stack" in RFC 9162 Section 2.1.2
        # represents. Thus, we can use an inclusion proof for the last entry at
        # tree_size to bootstrap our internal state to that point in time.

        leaf = log.get_leaves(start_index, start_index+1)[0]
        inclusion_proof = log.get_inclusion_proof(start_index + 1, leaf)
        if inclusion_proof.leaf_index != start_index:
            raise RuntimeError(f'unexpected leaf index in inclusion proof: {inclusion_proof.leaf_index} != {start_index}')

        mt = MerkleTree(start_index, list(reversed(inclusion_proof.node_hashes)))
        if tail:
            # Special case: Normally, start_index is the first leaf we will
            # fetch on a subsequent poll operation. However, when tailing the
            # log, we expect the first poll to be a no-op (barring tree-size
            # changes in the meantime), so we replay this leaf here after using
            # it for generating the initialization data above.

            mt.add_leaf(leaf.leaf_hash())

        return cls(log, mt)

    @classmethod
    def from_state(cls, log: SigsumLogAPI, state: dict[str, Any]):
        return cls(log, MerkleTree(
            state['tree']['size'],
            [bytes.fromhex(x) for x in state['tree']['stack']]
        ))

    def get_state(self) -> dict[str, Any]:
        return {
            'tree': {
                'size': self.tree.size,
                'stack': [x.hex() for x in self.tree.stack]
            }
        }

    def poll(self, batch_size: Optional[int] = None) -> tuple[int, list[TreeLeaf], int]:
        th = self.log.get_tree_head()
        if th.size == self.tree.size:
            return self.tree.size, [], 0

        logger.debug('tree increased from %d to %d, fetching leaves', self.tree.size, th.size)

        range_start = self.tree.size
        range_end = th.size
        if batch_size is not None and range_end - range_start > batch_size:
            range_end = range_start + batch_size

        logger.debug('fetching leaves in range [%d,%d)', range_start, range_end)
        leaves = self.log.get_leaves(range_start, range_end)
        logger.debug('got %d leaves', len(leaves))

        new_tree = copy.deepcopy(self.tree)
        for leaf in leaves:
            new_tree.add_leaf(leaf.leaf_hash())

        rh = new_tree.root_hash()
        if new_tree.size == th.size:
            if rh != th.root_hash:
                raise RuntimeError('root hash mismatch, ours: %s, theirs: %s', rh.hex(), th.root_hash.hex())
        else:
            cp = self.log.get_consistency_proof(new_tree.size, th.size)
            if not cp.check(rh, th.root_hash):
                raise RuntimeError('proof is invalid, proof was: %s', cp)

        logger.debug('validated head moved from %d to %d', self.tree.size, new_tree.size)
        self.tree = new_tree

        return range_start, leaves, th.size - self.tree.size
