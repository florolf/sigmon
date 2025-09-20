#!/usr/bin/env python3

import logging
import time
from dataclasses import dataclass
from collections import OrderedDict, defaultdict
from typing import Optional, Self

import nacl.signing
import nacl.exceptions

import requests

from .utils import sha256, b64enc
from .__about__ import VERSION as SIGMON_VERSION

logger = logging.getLogger(__name__)

def parse_ascii(doc: str) -> dict[str, list[list[str]]]:
    out = defaultdict(list)

    for line in doc.splitlines():
        if not line:
            continue

        key, value = line.split('=', 1)
        out[key].append(value.split())

    return out


@dataclass(frozen=True)
class TreeHead:
    size: int
    root_hash: bytes

    def __str__(self):
        return f"TreeHead(size={self.size}, root_hash={self.root_hash.hex()})"


@dataclass(frozen=True)
class TreeLeaf:
    checksum: bytes
    signature: bytes
    key_hash: bytes

    def leaf_hash(self):
        return sha256(b'\x00' + self.checksum + self.signature + self.key_hash)

    def __str__(self):
        return f"TreeLeaf(checksum={self.checksum.hex()}, key_hash={self.key_hash.hex()}, signature={self.signature.hex()})"


@dataclass(frozen=True)
class InclusionProof:
    leaf_index: int
    node_hashes: list[bytes]

    def __str__(self):
        hashes = ", ".join([x.hex() for x in self.node_hashes])
        return f"InclusionProof(leaf_index={self.leaf_index}, node_hashes=[{hashes}]"


@dataclass(frozen=True)
class ConsistencyProof:
    node_hashes: list[bytes]

    old_size: int
    new_size: int

    def __str__(self):
        hashes = ", ".join([x.hex() for x in self.node_hashes])
        return f"ConsistencyProof(old_size={self.old_size}, new_size={self.new_size}, node_hashes=[{hashes}]"

    def check(self, old_hash: bytes, new_hash: bytes) -> bool:
        # RFC 9162,  2.1.4.2. Verifying Consistency between Two Tree Heads

        # RFC names from here on
        consistency_path = self.node_hashes.copy()
        first = self.old_size
        second = self.new_size
        first_hash = old_hash
        second_hash = new_hash

        # 1. If consistency_path is an empty array, stop and fail the proof
        # verification.
        if not consistency_path:
            return False

        # 2. If first is an exact power of 2, then prepend first_hash to the
        # consistency_path array.
        if first & (first - 1) == 0:
            consistency_path.insert(0, first_hash)

        # 3. Set fn to first - 1 and sn to second - 1.
        fn = first - 1
        sn = second - 1

        # 4. If LSB(fn) is set, then right-shift both fn and sn equally until
        # LSB(fn) is not set.
        while (fn & 1) != 0:
            fn >>= 1
            sn >>= 1

        # 5. Set both fr and sr to the first value in the consistency_path
        # array.
        fr = consistency_path[0]
        sr = consistency_path[0]

        # 6. For each subsequent value c in the consistency_path array:
        for c in consistency_path[1:]:
            # a. If sn is 0, then stop the iteration and fail the proof
            # verification.
            if sn == 0:
                return False

            # b. If LSB(fn) is set, or if fn is equal to sn, then:
            if (fn & 1) == 1 or fn == sn:
                # i. Set fr to HASH(0x01 || c || fr).
                fr = sha256(b'\x01' + c + fr)

                # ii. Set sr to HASH(0x01 || c || sr).
                sr = sha256(b'\x01' + c + sr)

                # iii. If LSB(fn) is not set, then right-shift both fn and sn
                # equally until either LSB(fn) is set or fn is 0.
                if (fn & 1) == 0:
                    while True:
                        fn >>= 1
                        sn >>= 1

                        if (fn & 1) == 1 or fn == 0:
                            break
            # Otherwise:
            else:
                # i. Set sr to HASH(0x01 || sr || c).
                sr = sha256(b'\x01' + sr + c)

            # c. Finally, right-shift both fn and sn one time.
            fn >>= 1
            sn >>= 1

        # 7. After completing iterating through the consistency_path array as
        # described above, verify that the fr calculated is equal to the
        # first_hash supplied, that the sr calculated is equal to the
        # second_hash supplied, and that sn is 0.
        return fr == first_hash and sr == second_hash and sn == 0


class Quorum:
    def __init__(self, entities: OrderedDict[str, bytes|tuple[int, set[str]]], entry_point: str):
        self.entities = entities
        self.entry_point = entry_point

        self.key_hashes = {}
        for name, entity in entities.items():
            if not isinstance(entity, bytes):
                continue

            self.key_hashes[sha256(entity)] = name

    def get_witness(self, key_hash: bytes) -> Optional[tuple[str, bytes]]:
        if key_hash not in self.key_hashes:
            return None

        name = self.key_hashes[key_hash]
        entity = self.entities[name]

        if not isinstance(entity, bytes):
            return None

        return (name, entity)

    def check(self, witnesses: list[str]) -> bool:
        good = set(witnesses)

        # Because the input policy is already topologically sorted (you can
        # only refer to entities that are already defined), we can just make a
        # single pass and collect all the groups that are satisfied as we go.
        for name, entity in self.entities.items():
            if isinstance(entity, tuple):
                cardinality, members = entity
                if len(members & good) >= cardinality:
                    good.add(name)

        return self.entry_point in good


class SigsumLogAPI:
    def __init__(self, endpoint: str, pubkey: bytes, quorum: Optional[Quorum]):
        self.endpoint = endpoint
        self.pubkey = nacl.signing.VerifyKey(pubkey)
        self.key_hash = sha256(pubkey)

        self.session = requests.Session()
        self.session.headers['User-Agent'] = f'sigmon/{SIGMON_VERSION}'

        self.quorum = quorum

    @classmethod
    def from_policy(cls, policy: str, log_filter: Optional[str] = None) -> Self:
        log = None

        have_quorum = False
        quorum = None
        entities = OrderedDict()

        for line in policy.splitlines():
            if line.startswith('#'):
                continue

            match line.split():
                case ['log', key, url]:
                    if log_filter is not None and log_filter not in url:
                        continue

                    if log is not None:
                        raise ValueError('multiple matching log definitions in policy')

                    log = (url, bytes.fromhex(key))

                case ['quorum', entry_point]:
                    if have_quorum:
                        raise ValueError('multiple quorum definitions in policy')

                    have_quorum = True

                    if entry_point == 'none':
                        quorum = None
                    else:
                        if entry_point not in entities:
                            raise ValueError(f'quorum entry point "{entry_point}" is unknown')

                        quorum = Quorum(entities, entry_point)

                case ['witness', name, pubkey, *url]:
                    if name == 'none':
                        raise ValueError('quorum entity name "none" is reserved')

                    if name in entities:
                        raise ValueError(f'quorum entity "{name}" already exists')

                    entities[name] = bytes.fromhex(pubkey)

                case ['group', name, cardinality, *members]:
                    if name == 'none':
                        raise ValueError('quorum entity name "none" is reserved')

                    if name in entities:
                        raise ValueError(f'quorum entity "{name}" already exists')

                    if len(members) == 0:
                        raise ValueError(f'group "{name}" has no members')

                    if cardinality == 'all':
                        cardinality = len(members)
                    elif cardinality == 'any':
                        cardinality = 1
                    else:
                        cardinality = int(cardinality)

                    for member in members:
                        if member not in entities:
                            raise ValueError(f'group "{name}" refers to unknown entity "{member}"')

                    entities[name] = (cardinality, set(members))

                case [unknown, *_]:
                    raise ValueError(f'unknown policy command "{unknown}"')

        if log is None:
            raise ValueError('no log found in policy')

        if not have_quorum:
            raise ValueError('quorum not specified')

        return cls(*log, quorum)

    def do_request(self, *args, timeout=60) -> dict[str, list[list[str]]]:
        url = '/'.join([self.endpoint, *[str(x) for x in args]])

        backoff = 1
        deadline = time.time() + timeout
        while True:
            remaining = max(0, deadline - time.time())

            resp = self.session.get(url, timeout=remaining)
            if resp.status_code == 429:
                if time.time() + backoff < deadline:
                    time.sleep(backoff)
                    backoff *= 2
                    continue

            resp.raise_for_status()
            return parse_ascii(resp.text)

    def get_tree_head(self) -> TreeHead:
        th = self.do_request('get-tree-head')

        root_hash = bytes.fromhex(th['root_hash'][0][0])
        if len(root_hash) != 32:
            raise ValueError(f'unexpected root_hash length: {len(root_hash)} != 32')

        size = int(th['size'][0][0])
        if size < 0:
            raise ValueError(f'negative tree size: {size}')

        signature = bytes.fromhex(th['signature'][0][0])

        th_commitment = f"sigsum.org/v1/tree/{self.key_hash.hex()}\n{size}\n{b64enc(root_hash)}\n"
        self.pubkey.verify(th_commitment.encode(), signature)

        if self.quorum is not None:
            happy_witnesses = []
            for key_hash, timestamp, signature in th['cosignature']:
                witness = self.quorum.get_witness(bytes.fromhex(key_hash))
                if witness is None:
                    continue

                name = witness[0]
                pk = nacl.signing.VerifyKey(witness[1])

                timestamp = int(timestamp)
                signature = bytes.fromhex(signature)

                witness_commitment = f"cosignature/v1\ntime {timestamp}\n{th_commitment}"
                try:
                    pk.verify(witness_commitment.encode(), signature)
                    happy_witnesses.append(name)
                except nacl.exceptions.BadSignatureError:
                    logger.warning('invalid witness cosignature from %s over "%s": %s',
                                   name, witness_commitment, signature.hex())

            if not self.quorum.check(happy_witnesses):
                raise ValueError('quorum not reached')

        return TreeHead(size, root_hash)

    def get_leaves(self, start: int, end: int) -> list[TreeLeaf]:
        leaves = self.do_request('get-leaves', start, end)['leaf']

        result = []
        for checksum, signature, key_hash in leaves:
            result.append(TreeLeaf(
                bytes.fromhex(checksum),
                bytes.fromhex(signature),
                bytes.fromhex(key_hash),
            ))

        return result

    def get_inclusion_proof(self, size: int, leaf: TreeLeaf) -> InclusionProof:
        proof = self.do_request('get-inclusion-proof', size, leaf.leaf_hash().hex())

        leaf_index = int(proof['leaf_index'][0][0])
        if leaf_index < 0:
            raise ValueError(f'negative leaf index: {leaf_index}')

        node_hashes = [bytes.fromhex(x[0]) for x in proof['node_hash']]

        return InclusionProof(leaf_index, node_hashes)

    def get_consistency_proof(self, old_size: int, new_size: int) -> ConsistencyProof:
        proof = self.do_request('get-consistency-proof', old_size, new_size)

        return ConsistencyProof(
            [bytes.fromhex(x[0]) for x in proof['node_hash']],
            old_size,
            new_size
        )
