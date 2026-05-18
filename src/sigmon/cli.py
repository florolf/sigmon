#!/usr/bin/env python3

import sys
import logging
import argparse
import json
import os
import time
from typing import Any, Optional
from pathlib import Path
import subprocess

import nacl.signing
import nacl.exceptions

from .sigsum import SigsumLogAPI, TreeLeaf, QuorumPolicy, QuorumUnsatisfiedError
from .monitor import Monitor
from .utils import sha256

from . import utils, config

logger = logging.getLogger(__name__)

class State:
    def __init__(self, path: Path):
        self.path = path
        self.data = {}

    def load(self):
        with self.path.open('r') as f:
            self.data = json.load(f)

    def save(self):
        data = json.dumps(self.data, sort_keys=True, indent=True)
        utils.atomic_write(self.path, data.encode())

    def get_dict(self, path):
        cur = self.data

        for elem in path:
            if elem not in cur:
                cur[elem] = {}

            cur = cur[elem]

        return cur

    def __getitem__(self, path):
        if not isinstance(path, tuple):
            path = (path,)

        d = self.get_dict(path[:-1])
        return d[path[-1]]

    def get(self, path: list[str], default):
        d = self.get_dict(path[:-1])
        return d.get(path[-1], default)

    def __setitem__(self, path, value):
        if not isinstance(path, tuple):
            path = (path,)

        d = self.get_dict(path[:-1])
        d[path[-1]] = value

    def __contains__(self, path):
        if not isinstance(path, tuple):
            path = (path,)

        d = self.get_dict(path[:-1])
        return path[-1] in d


def build_parser():
    parser = argparse.ArgumentParser(prog="sigmon", description="Monitor Sigsum logs")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    subparsers = parser.add_subparsers(title="subcommands", dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Initialize monitor state")
    init_parser.add_argument("state_dir", type=Path, help="Path to config/state directory")
    init_parser.add_argument("leaf_index", nargs="?", type=int, help="Index of first leaf to fetch (default: tail the log)")
    init_parser.add_argument("-f", "--force", action="store_true", help="Force reinitialization even if state is present")
    init_parser.add_argument("--log", metavar='URL', help="Select a specific log from the policy file (URL or unique substring thereof)")

    poll_parser = subparsers.add_parser("poll", help="Poll for new log entries")
    poll_parser.add_argument("state_dir", type=Path, help="Path to config/state directory")
    poll_parser.add_argument("--batch-size", type=int, default=None, help="Limit maximum number of leaves to fetch at once")
    poll_parser.add_argument("--max-stale", type=int, default=None, help="Maximum age of the latest tree head before sending an alert")
    poll_parser.add_argument("-i", "--interval", type=float, metavar="SECONDS", help="Polling interval in seconds. If omitted, do a single poll and exit.")
    poll_parser.add_argument("--log", metavar='URL', help="Select a specific log from the policy file (URL or unique substring thereof)")

    return parser


def do_init(args: argparse.Namespace):
    with open(args.state_dir / 'policy', 'r') as f:
        log = SigsumLogAPI.from_policy(f.read(), log_filter=args.log)

    log_dir = args.state_dir / 'log'
    log_dir.mkdir(exist_ok=True)

    state_file = log_dir / f'{bytes(log.pubkey.key).hex()}.json'
    if state_file.exists() and not args.force:
        logger.error("%s exists and --force is not given", state_file)
        sys.exit(1)

    state = State(state_file)

    monitor = Monitor.from_log(log, args.leaf_index)
    state['monitor'] = monitor.get_state()

    state.save()


def call_hook(state_dir: Path, hook_type: str, hook_name: str, env: dict[str, str], run_args: Optional[dict[str, Any]] = None) -> Optional[Any]:
    hook_path = (state_dir / 'hooks' / hook_type / hook_name)
    resolved = hook_path.resolve()
    if not resolved.exists():
        logging.warning(f'{hook_type} hook "{hook_name}" does not exist')
        return None

    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        logging.warning(f'{hook_type} hook "{hook_name}" is not executable')
        return None

    merged_env = os.environ.copy()
    merged_env.update(env)

    if run_args is None:
        run_args = {}

    ret = subprocess.run([str(hook_path)], cwd=state_dir, env=merged_env, **run_args)
    if ret.returncode != 0:
        logger.warning(f'{hook_type} hook "{hook_name}" failed, exit code {ret.returncode}')

    return ret


def call_all_hooks(state_dir: Path, hook_type: str, env: dict[str, str]):
    hook_dir = state_dir / 'hooks' / hook_type
    if not hook_dir.exists():
        return

    for child in sorted(hook_dir.iterdir()):
        call_hook(state_dir, hook_type, child.name, env)


def handle_match(state_dir: Path, log: str, idx: int, match: config.KeyEntry, leaf: TreeLeaf):
    env: dict[str, str] = {
        'LOG_ENDPOINT': log,
        'LEAF_INDEX': str(idx),
        'LEAF_CHECKSUM': leaf.checksum.hex(),
        'LEAF_SIGNATURE': leaf.signature.hex(),
        'KEY_HASH': leaf.key_hash.hex(),
        'KEY_NAME': match.name,
    }

    for k, v in match.attrs.items():
        env[f'KEY_ATTR_{k}'] = v

    if match.key is not None:
        env['KEY'] = match.key.hex()

        verify_key = nacl.signing.VerifyKey(match.key)
        try:
            verify_key.verify(b'sigsum.org/v1/tree-leaf\x00' + leaf.checksum, leaf.signature)
            env['LEAF_SIGNATURE_VALID'] = '1'
        except nacl.exceptions.BadSignatureError:
            logger.warning(f'signature check on leaf {leaf}, idx {idx} failed')
            env['LEAF_SIGNATURE_VALID'] = '0'

    for hook in match.hooks:
        hook_env = env.copy()
        for k, v in hook.params.items():
            hook_env[f'HOOK_PARAM_{k}'] = v

        if hook.kind == 'leaf_info':
            result = call_hook(state_dir, 'leaf_info', hook.name, hook_env, run_args={
                'stdout': subprocess.PIPE,
                'text': True,
            })

            if result is None or  result.returncode != 0:
                continue

            if result.stdout:
                env[f'LEAF_INFO_{hook.name}'] = result.stdout.strip()
        else:
            call_hook(state_dir, 'match', hook.name, hook_env)


def do_poll(args: argparse.Namespace):
    with open(args.state_dir / 'policy', 'r') as f:
        policy_text = f.read()

        log = SigsumLogAPI.from_policy(policy_text, log_filter=args.log)
        policy = QuorumPolicy.from_policy(policy_text)

    state = State(args.state_dir / 'log' / f'{bytes(log.pubkey.key).hex()}.json')
    state.load()

    watchlist = args.state_dir / 'watchlist.kdl'
    watchlist_ts = None
    matches = {}

    monitor = Monitor.from_state(log, state['monitor'])

    while True:
        if watchlist.exists():
            mtime = watchlist.stat().st_mtime
            if watchlist_ts is None or mtime > watchlist_ts:
                if watchlist_ts is not None:
                    logger.info('reloading watchlist')

                try:
                    matches = config.load_config(watchlist)
                except Exception as e:
                    logger.error('reloading matches failed', exc_info=e)

                watchlist_ts = mtime

        while True:
            th = None
            try:
                th, start_idx, leaves, remaining = monitor.poll(batch_size=args.batch_size)
            except Exception as e:
                logger.error('poll cycle failed', exc_info=e)
                break

            for idx, leaf in enumerate(leaves, start=start_idx):
                if leaf.key_hash not in matches:
                    continue

                match = matches[leaf.key_hash]
                logger.info(f'index {idx} matched key {match.name}, checksum is {leaf.checksum.hex()}')

                handle_match(args.state_dir, log.endpoint, idx, match, leaf)

            state['monitor'] = monitor.get_state()
            state.save()

            if not remaining:
                break

        if th is not None:
            try:
                quorum = policy.check(th)
                state['health', 'last_success'] = quorum.timestamp
            except QuorumUnsatisfiedError:
                logging.error(f'quorum not satisfied for treehead {th}')

            for cs in th.cosignatures:
                if not cs.valid:
                    continue

                key_hash = cs.key_hash.hex()
                old = state.get(['health', 'cs', key_hash], None)
                if old is None or old['ts'] <= cs.timestamp:
                    state['health', 'cs', key_hash] = {
                        'ts': cs.timestamp,
                        'size': th.size
                    }

            state.save()


        last_success = state.get(['health', 'last_success'], None)
        if last_success is not None and args.max_stale is not None:
            last_success_age = int(time.time()) - last_success
            stale_active = state.get(['alerts', 'stale_active'], False)

            env = {
                'LOG_ENDPOINT': log.endpoint,
                'TYPE': 'stale',
                'LAST_SUCCESS_AGE': str(last_success_age),
                'LAST_SUCCESS': str(last_success),
            }

            if last_success_age > args.max_stale and not stale_active:
                logger.error(f'log is stale: last success at {last_success}, {last_success_age} seconds ago')

                env['STATE'] = 'failed'
                call_all_hooks(args.state_dir, 'log_health', env)

                state['alerts', 'stale_active'] = True
                state.save()

            if last_success_age <= args.max_stale and stale_active:
                logger.info('log has recovered from being stale')

                env['STATE'] = 'okay'
                call_all_hooks(args.state_dir, 'log_health', env)

                state['alerts', 'stale_active'] = False
                state.save()

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
