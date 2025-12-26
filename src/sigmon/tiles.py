#!/usr/bin/env python3

from pathlib import Path
from typing import Optional, Self
from dataclasses import dataclass
import shutil
import typing
import nacl.signing

from .utils import sha256, b64enc, b64dec
from . import utils

@dataclass(frozen=True)
class Checkpoint:
    origin: str
    tree_size: int
    root_hash: bytes

    @classmethod
    def from_text(cls, text: str) -> Self:
        lines = text.splitlines()

        origin = lines[0]
        tree_size = int(lines[1])
        root_hash = b64dec(lines[2])

        return cls(origin, tree_size, root_hash)

    def to_text(self, signatures: Optional[list[str]] = None) -> str:
        out = ""
        out += "%s\n" % self.origin
        out += "%d\n" % self.tree_size
        out += b64enc(self.root_hash) + "\n"

        if signatures:
            out += "\n"

            for sig in signatures:
                out += f'{sig}\n'

        return out


class Ed25519Signer:
    def __init__(self, name: str, privkey: bytes):
        self.name = name
        self.key = nacl.signing.SigningKey(privkey)

    @classmethod
    def generate(cls, name: str) -> Self:
        priv = nacl.signing.SigningKey.generate()
        return cls(name, bytes(priv))

    def key_id(self) -> bytes:
        h = sha256(self.name.encode() + b'\x0a\x01' + bytes(self.key.verify_key))
        return h[:4]

    def vkey(self) -> str:
        keydata = b'\x01' + bytes(self.key.verify_key)
        return f'{self.name}+{self.key_id().hex()}+{b64enc(keydata)}'

    def sign_note(self, data: bytes) -> str:
        sig = self.key.sign(data).signature

        return f'\u2014 {self.name} {b64enc(self.key_id() + sig)}'

    def sign_checkpoint(self, cp: Checkpoint) -> str:
        data = cp.to_text()
        return self.sign_note(data.encode())


class FakeVKey:
    def __init__(self, name: str, pubkey: bytes, witness: bool):
        self.name = name
        self.pubkey = pubkey
        self.witness = witness

    def key_id(self) -> bytes:
        if self.witness:
            type_ = 0x04
        else:
            type_ = 0x01

        h = sha256(self.name.encode() + b'\x0a' + type_.to_bytes() + self.pubkey)
        return h[:4]

    def vkey(self) -> str:
        if self.witness:
            type_ = 0x04
        else:
            type_ = 0x01

        return f'{self.name}+{self.key_id().hex()}+{b64enc(type_.to_bytes()+self.pubkey)}'

    def wrap_sig(self, sig: bytes, timestamp: Optional[int] = None) -> str:
        if self.witness:
            if timestamp is None:
                raise ValueError('timestamp required')

            payload = timestamp.to_bytes(8) + sig
        else:
            payload = sig

        return f'\u2014 {self.name} {b64enc(self.key_id() + payload)}'


class Tiles:
    def __init__(self, base: Path):
        self.base = base
        self.pending = []

        cp_path = base / "checkpoint"
        cp = Checkpoint.from_text(cp_path.read_text())
        self.tree_size = cp.tree_size
        self.origin = cp.origin

    @classmethod
    def new_empty(cls, base: Path, origin: str) -> Self:
        base.mkdir()

        cp = Checkpoint(origin, 0, sha256(b''))
        utils.sync_write(base / "checkpoint", cp.to_text().encode())

        return cls(base)

    def add_leaf(self, data: bytes) -> None:
        self.pending.append(data)

    def tile_path(self, level: int, index: int, partial: int = 0) -> Path:
        base = self.base / 'tile'
        if level == -1:
            base = base / 'entries'
        else:
            base = base / ('%d' % level)

        elements = []
        first = True

        while True:
            cur = '%03d' % (index % 1000)
            index = index // 1000

            if first:
                first = False
            else:
                cur = 'x'+ cur

            elements.append(cur)

            if not index:
                break

        elements.reverse()
        if partial:
            elements[-1] += '.p'
            elements.append('%d' % partial)

        return Path(base, *elements)

    def level_entries_cnt(self, level: int) -> int:
        if level == -1:
            level = 0

        return self.tree_size // 256**level

    def level_tiles(self, level: int) -> tuple[int, int]:
        entries = self.level_entries_cnt(level)

        # number of completed tiles or index of the current tile
        complete_tiles, partial = divmod(entries, 256)
        return complete_tiles, partial

    def append_tile(self, level: int, elements: list[bytes], cleanup: bool = True):
        if not elements:
            return

        current_tile, partial = self.level_tiles(level)

        # fill up and potentially complete an existing partial tile
        if partial:
            old_data = self.tile_path(level, current_tile, partial).read_bytes()

            max_this = 256 - partial
            this, elements = elements[:max_this], elements[max_this:]

            new_size = partial + len(this)

            if new_size == 256:
                this_path = self.tile_path(level, current_tile, 0)
                current_tile += 1
                can_cleanup = True
            else:
                this_path = self.tile_path(level, current_tile, new_size)
                can_cleanup = False

            utils.sync_write(this_path, old_data + b''.join(this))

            if cleanup and can_cleanup:
                shutil.rmtree(this_path.with_suffix('.p'))

        # write full tiles and potentially a new partial
        while elements:
            this, elements = elements[:256], elements[256:]

            if len(this) == 256:
                this_path = self.tile_path(level, current_tile, 0)
                current_tile += 1
            else:
                this_path = self.tile_path(level, current_tile, len(this))

            this_path.parent.mkdir(parents=True, exist_ok=True)
            utils.sync_write(this_path, b''.join(this))

    @staticmethod
    def merkle_merge(data: bytes) -> bytes:
        l = [data[i:i+32] for i in range(0, len(data), 32)]

        while len(l) > 1:
            left = l.pop(0)
            right = l.pop(0)

            h = sha256(b'\x01' + left + right)
            l.append(h)

        return l[0]

    def hash_tile(self, level: int, index: int) -> bytes:
        if level < 0:
            raise ValueError('level must be >= 0, is %d' % level)

        tile_data = self.tile_path(level, index).read_bytes()
        assert len(tile_data) == 8192

        return self.merkle_merge(tile_data)

    def load_tile(self, level: int, entry_idx: int) -> tuple[bytes, int]:
        level_entries = self.level_entries_cnt(level)
        current_tile, current_partial_size = divmod(level_entries, 256)
        tile, tile_offset = divmod(entry_idx, 256)

        if tile < current_tile:
            path = self.tile_path(level, tile)
        elif tile == current_tile and tile_offset < current_partial_size:
            path = self.tile_path(level, current_tile, current_partial_size)
        else:
            raise ValueError(f'entry index {entry_idx} ({tile}:{tile_offset}) out of range on level {level}, which has {tile} full tiles and a partial size of {current_partial_size}')

        return path.read_bytes(), tile_offset

    def get_node(self, micro_level: int, index: int) -> bytes:
        level_entries = self.tree_size // 2**micro_level
        if index >= level_entries:
            raise ValueError(f'tree level {micro_level} only has {level_entries} entries, {index} is out of bounds')

        base_level, level_offset = divmod(micro_level, 8)
        base_index = index * 2**level_offset
        data, entry_offset = self.load_tile(base_level, base_index)

        entries_cnt = 2**level_offset

        return self.merkle_merge(
            data[entry_offset * 32:(entry_offset + entries_cnt) * 32]
        )

    def get_root_hash(self) -> bytes:
        i = self.tree_size

        if i == 0:
            return sha256(b'')

        right = None
        while i:
            lsb = (i&-i).bit_length() - 1
            size = 1<<lsb
            i -= size

            level = lsb
            idx = i >> lsb

            if right is None:
                right = self.get_node(level, idx)
            else:
                left = self.get_node(level, idx)
                right = sha256(b'\x01' + left + right)

        # right can't be None here since we handled the i == 0 case above
        return typing.cast(bytes, right)

    def commit(self, signatures: Optional[list[str]] = None) -> None:
        entries = []
        for leaf in self.pending:
            entries.append(len(leaf).to_bytes(length=2) + leaf)
        self.append_tile(-1, entries)

        entries = []
        for leaf in self.pending:
            entries.append(sha256(b'\x00' + leaf))
        self.append_tile(0, entries)

        new_size = self.tree_size + len(self.pending)

        old_full_tiles = self.tree_size // 256
        new_full_tiles = new_size // 256
        level = 1
        while old_full_tiles != new_full_tiles:
            entries = []
            for idx in range(old_full_tiles, new_full_tiles):
                entries.append(self.hash_tile(level-1, idx))

            self.append_tile(level, entries)

            level += 1
            old_full_tiles //= 256
            new_full_tiles //= 256

        self.tree_size = new_size
        self.pending = []

        cp = Checkpoint(self.origin, self.tree_size, self.get_root_hash())
        utils.sync_write(self.base / "checkpoint", cp.to_text(signatures).encode())
