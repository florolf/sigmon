#!/usr/bin/env python3

import sys
import logging
import argparse
import json
import os
import time
from typing import Any
from pathlib import Path
import tempfile
import subprocess

import nacl.signing
import nacl.exceptions

from .sigsum import SigsumLogAPI, TreeLeaf
from .monitor import Monitor
from .utils import sha256

logger = logging.getLogger(__name__)

def write_json_atomic(path: Path, data: Any):
    path = path.resolve()

    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as f:
        json.dump(data, f, sort_keys=True, indent=True)
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


def build_parser():
    parser = argparse.ArgumentParser(prog="sigmon", description="Monitor Sigsum logs")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    subparsers = parser.add_subparsers(title="subcommands", dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Initialize monitor state")
    init_parser.add_argument("state_dir", type=Path, help="Path to config/state directory")
    init_parser.add_argument("leaf_index", nargs="?", type=int, help="Index of first leaf to fetch (default: tail the log)")
    init_parser.add_argument("-f", "--force", action="store_true", help="Force reinitialization even if state is present")

    poll_parser = subparsers.add_parser("poll", help="Poll for new log entries")
    poll_parser.add_argument("state_dir", type=Path, help="Path to config/state directory")
    poll_parser.add_argument("--batch-size", type=int, default=None, help="Limit maximum number of leaves to fetch at once")
    poll_parser.add_argument("-i", "--interval", type=float, metavar="SECONDS", help="Polling interval in seconds. If omitted, do a single poll and exit.")

    return parser


def load_matches(path: Path) -> dict[str, dict[str, Any]]:
    matches = {}

    with open(path, 'r') as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()

            items = line.split()

            match items[0]:
                case 'keyhash':
                    keyhash = bytes.fromhex(items[1])
                    if len(keyhash) != 32:
                        raise ValueError(f'malformed key hash in line {lineno}: unexpected length {len(keyhash)}')

                    key = None

                case 'key':
                    key = bytes.fromhex(items[1])
                    if len(key) != 32:
                        raise ValueError(f'malformed key in line {lineno}: unexpected length {len(key)}')

                    keyhash = sha256(key)

                case _:
                    raise ValueError(f'unknown match type {items[0]} in line {lineno}')

            if keyhash in matches:
                raise ValueError(f'key hash added in line {lineno} is {keyhash.hex()} already present')
            else:
                matches[keyhash] = {}

            if key is not None:
                matches[keyhash]['_key'] = key

            for attr in items[2:]:
                k, v = attr.split('=', maxsplit=1)

                if k.startswith('_'):
                    raise ValueError(f'key {k} uses reserved prefix')

                matches[keyhash][k] = v

    return matches


def do_init(args: argparse.Namespace):
    state_file = args.state_dir / 'state.json'
    if state_file.exists() and not args.force:
        logger.error("%s exists and --force is not given", state_file)
        sys.exit(1)

    with open(args.state_dir / 'policy', 'r') as f:
        log = SigsumLogAPI.from_policy(f.read())

    monitor = Monitor.from_log(log, args.leaf_index)
    write_json_atomic(state_file, monitor.get_state())


def call_hooks(state_dir: Path, hook_type: str, env: dict[str, str]):
    merged_env = os.environ.copy()
    merged_env.update(env)

    hook_dir = state_dir / 'hooks' / hook_type
    if not hook_dir.exists():
        return

    for child in sorted(hook_dir.iterdir()):
        child = child.resolve()
        if not child.is_file():
            continue

        if not os.access(child, os.X_OK):
            continue

        subprocess.run([str(child)], cwd=state_dir, env=merged_env)


def handle_match(state_dir: Path, log: str, idx: int, match: dict[str, Any], leaf: TreeLeaf):
    env: dict[str, str] = {
        'LOG_ENDPOINT': log,
        'LEAF_INDEX': str(idx),
        'LEAF_CHECKSUM': leaf.checksum.hex(),
        'LEAF_SIGNATURE': leaf.signature.hex(),
        'KEY_HASH': leaf.key_hash.hex(),
    }

    for k, v in match.items():
        if k.startswith('_'):
            continue

        env[f'KEY_ATTR_{k}'] = v

    if '_key' in match:
        env['KEY'] = match['_key'].hex()

        verify_key = nacl.signing.VerifyKey(match['_key'])
        try:
            verify_key.verify(b'sigsum.org/v1/tree-leaf\x00' + leaf.checksum, leaf.signature)
            env['LEAF_SIGNATURE_VALID'] = '1'
        except nacl.exceptions.BadSignatureError:
            logger.warning(f'signature check on leaf {leaf}, idx {idx} failed')
            env['LEAF_SIGNATURE_VALID'] = '0'

    call_hooks(state_dir, 'match', env)


def do_poll(args: argparse.Namespace):
    with open(args.state_dir / 'policy', 'r') as f:
        log = SigsumLogAPI.from_policy(f.read())

    state_file = args.state_dir / 'state.json'
    with open(state_file, 'r') as f:
        state = json.load(f)

    watchlist = args.state_dir / 'watchlist'
    watchlist_ts = None
    matches = {}

    monitor = Monitor.from_state(log, state)

    while True:
        if watchlist.exists():
            mtime = watchlist.stat().st_mtime
            if watchlist_ts is None or mtime > watchlist_ts:
                if watchlist_ts is not None:
                    logger.info('reloading watchlist')

                matches = load_matches(args.state_dir / 'watchlist')
                watchlist_ts = mtime

        while True:
            try:
                start_idx, leaves, remaining = monitor.poll(batch_size=args.batch_size)
            except Exception as e:
                logger.error('poll cycle failed', exc_info=e)
                break

            for idx, leaf in enumerate(leaves):
                if leaf.key_hash not in matches:
                    continue

                match = matches[leaf.key_hash]
                logger.info(f'index {idx} matched key {match["alias"] if "alias" in match else leaf.key_hash.hex()}, checksum is {leaf.checksum.hex()}')

                handle_match(args.state_dir, log.endpoint, start_idx+idx, match, leaf)

            write_json_atomic(state_file, monitor.get_state())

            if not remaining:
                break

            # TODO: what would be a reasonable back-off strategy here given
            # that we need to catch up in a finite amount of time
            time.sleep(1)

        if args.interval is None:
            break

        time.sleep(args.interval)


def main():
    args = build_parser().parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    match args.command:
        case 'init':
            do_init(args)
        case 'poll':
            do_poll(args)
