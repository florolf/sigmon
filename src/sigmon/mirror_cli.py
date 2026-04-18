#!/usr/bin/env python3

import sys
import logging
import argparse
import time
from pathlib import Path

from .sigsum import SigsumLogAPI, QuorumPolicy
from .monitor import Monitor
from .utils import sha256
from .cli import State
from . import tiles

logger = logging.getLogger(__name__)

def build_parser():
    parser = argparse.ArgumentParser(prog="sigmon-mirror", description="Mirror Sigsum logs to tlog-tiles format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    subparsers = parser.add_subparsers(title="subcommands", dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Initialize mirror state")
    init_parser.add_argument("mirror_dir", type=Path, help="Path to mirror output directory")
    init_parser.add_argument("policy", type=Path, help="Path to policy file")
    init_parser.add_argument("--log", metavar='URL', help="Select a specific log from the policy file (URL or unique substring thereof)")

    poll_parser = subparsers.add_parser("poll", help="Poll for new log entries and update mirror")
    poll_parser.add_argument("mirror_dir", type=Path, help="Path to mirror directory")
    poll_parser.add_argument("--batch-size", type=int, default=None, help="Limit maximum number of leaves to fetch at once")
    poll_parser.add_argument("-i", "--interval", type=float, metavar="SECONDS", help="Polling interval in seconds. If omitted, do a single poll and exit.")

    return parser


def do_init(args: argparse.Namespace):
    with open(args.policy, 'r') as f:
        log = SigsumLogAPI.from_policy(f.read(), log_filter=args.log)

    if args.mirror_dir.exists():
        logger.error(f"{args.mirror_dir} already exists")
        sys.exit(1)

    origin = f'sigsum.org/v1/tree/{sha256(bytes(log.pubkey.key)).hex()}'
    tiles.Tiles.new_empty(args.mirror_dir, origin)

    sigmon_dir = args.mirror_dir / '.sigmon'
    sigmon_dir.mkdir()

    state = State(sigmon_dir / 'state.json')
    monitor = Monitor.from_log(log, 0)
    state['monitor'] = monitor.get_state()
    state['endpoint'] = log.endpoint
    state.save()

    args.policy.copy(sigmon_dir / 'policy')

    logger.info(f"Initialized mirror for log {log.endpoint}")


def do_poll(args: argparse.Namespace):
    sigmon_dir = args.mirror_dir / '.sigmon'

    state_file = sigmon_dir / 'state.json'
    if not state_file.exists():
        logger.error("Mirror not initialized. Run 'init' first.")
        sys.exit(1)

    state = State(state_file)
    state.load()

    policy = (sigmon_dir / 'policy').read_text()
    log = SigsumLogAPI.from_policy(policy, log_filter=state['endpoint'])
    quorum = QuorumPolicy.from_policy(policy)

    tiles_state = tiles.Tiles(args.mirror_dir)
    log_vkey = tiles.FakeVKey(log.endpoint.split('//')[1], bytes(log.pubkey.key), False)

    witness_vkeys: dict[bytes, tiles.FakeVKey] = {}
    for name, entity in quorum.entities.items():
        if not isinstance(entity, bytes):
            continue

        witness_vkeys[sha256(entity)] = tiles.FakeVKey(name, entity, True)

    with (tiles_state.base / 'vkeys.txt').open('w') as f:
        print(f'Log vkey: {log_vkey.vkey()}', file=f)
        print('Witness vkeys:', file=f)
        vkeys = [vkey.vkey() for vkey in witness_vkeys.values()]
        for vkey in sorted(vkeys):
            print(" - " + vkey, file=f)

    monitor = Monitor.from_state(log, state['monitor'])

    while True:
        while True:
            try:
                th, start_idx, leaves, remaining = monitor.poll(batch_size=args.batch_size)
            except Exception as e:
                logger.error('poll cycle failed', exc_info=e)
                if args.interval is None:
                    sys.exit(1)
                else:
                    time.sleep(args.interval)
                    continue

            if leaves:
                logger.info(f'Fetched {len(leaves)} leaves starting at index {start_idx}')

                for leaf in leaves:
                    tiles_state.add_leaf(leaf.serialize())

            if not remaining:
                break

        # commit
        signatures = []
        for cosig in th.cosignatures:
            if cosig.key_hash in witness_vkeys:
                witness_vkey = witness_vkeys[cosig.key_hash]
                signatures.append(witness_vkey.wrap_sig(cosig.signature, cosig.timestamp))

        signatures.sort()
        signatures.insert(0, log_vkey.wrap_sig(th.signature))
        tiles_state.commit(signatures)

        state['monitor'] = monitor.get_state()
        state.save()

        if leaves:
            logger.info(f'Updated mirror to tree size {tiles_state.tree_size}')

        if args.interval is not None:
            time.sleep(args.interval)
        else:
            break


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


if __name__ == '__main__':
    main()
