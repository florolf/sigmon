import argparse
from pathlib import Path

import nacl.signing

from sigmon import cli
from sigmon.utils import sha256

from fake_log import FakeSigsumLog, FakeWitness
from utils import make_leaf, make_valid_leaf

def _make_hook(state_dir: Path, hook_type: str, name: str, body: str) -> None:
    hook_dir = state_dir / 'hooks' / hook_type
    hook_dir.mkdir(parents=True, exist_ok=True)
    script = hook_dir / name
    script.write_text('#!/bin/sh\n' + body + '\n')
    script.chmod(0o755)


def _init_args(state_dir: Path, leaf_index=None, force=False) -> argparse.Namespace:
    return argparse.Namespace(
        state_dir=state_dir,
        leaf_index=leaf_index,
        force=force,
        log=None,
    )


def _poll_args(state_dir: Path, batch_size=None, max_stale=None) -> argparse.Namespace:
    return argparse.Namespace(
        state_dir=state_dir,
        batch_size=batch_size,
        max_stale=max_stale,
        interval=None,
        log=None,
    )


def test_do_poll_fires_match_hook(state_dir: Path, fake_log: FakeSigsumLog):
    cli.do_init(_init_args(state_dir, leaf_index=0))

    target_kh = b'\x11' * 32
    (state_dir / 'watchlist').write_text(
        f'keyhash {target_kh.hex()} alias=target\n'
    )
    _make_hook(
        state_dir,
        'match',
        'record',
        'echo "$LEAF_INDEX $KEY_HASH $KEY_ATTR_alias" >> matches.log',
    )

    fake_log.append(make_leaf(0, key_hash=b'\xaa' * 32))
    fake_log.append(make_leaf(1, key_hash=target_kh))
    fake_log.append(make_leaf(2, key_hash=b'\xbb' * 32))
    fake_log.append(make_leaf(3, key_hash=target_kh))

    cli.do_poll(_poll_args(state_dir))

    lines = (state_dir / 'matches.log').read_text().splitlines()
    assert lines == [
        f'1 {target_kh.hex()} target',
        f'3 {target_kh.hex()} target',
    ]


def test_do_poll_check_sig(state_dir: Path, fake_log: FakeSigsumLog):
    cli.do_init(_init_args(state_dir, leaf_index=0))

    leaf_key = nacl.signing.SigningKey.generate()

    (state_dir / 'watchlist').write_text(
        f'key {bytes(leaf_key.verify_key).hex()} alias=target\n'
    )
    _make_hook(
        state_dir,
        'match',
        'record',
        'echo "$LEAF_INDEX $LEAF_SIGNATURE_VALID" >> matches.log',
    )

    fake_log.append(make_leaf(0, key_hash=b'\xaa' * 32))
    fake_log.append(make_valid_leaf(1, leaf_key))
    fake_log.append(make_leaf(2, key_hash=b'\xbb' * 32))
    fake_log.append(make_leaf(3, key_hash=sha256(bytes(leaf_key.verify_key))))

    cli.do_poll(_poll_args(state_dir))

    lines = (state_dir / 'matches.log').read_text().splitlines()
    assert lines == [
        f'1 1',
        f'3 0',
    ]


def test_do_poll_still_fires_match_without_quorum(
    state_dir: Path, fake_log: FakeSigsumLog, caplog
):
    witness_pubkey = b'\x11' * 32
    (state_dir / 'policy').write_text(
        f'{fake_log.policy_line()}\n'
        f'witness w1 {witness_pubkey.hex()}\n'
        f'quorum w1\n'
    )

    cli.do_init(_init_args(state_dir, leaf_index=0))

    target_kh = b'\x11' * 32
    (state_dir / 'watchlist').write_text(
        f'keyhash {target_kh.hex()} alias=target\n'
    )
    _make_hook(
        state_dir,
        'match',
        'record',
        'echo "$LEAF_INDEX $KEY_HASH" >> matches.log',
    )

    fake_log.append(make_leaf(0, key_hash=b'\xaa' * 32))
    fake_log.append(make_leaf(1, key_hash=target_kh))

    with caplog.at_level('ERROR'):
        cli.do_poll(_poll_args(state_dir))

    assert (state_dir / 'matches.log').read_text().splitlines() == [
        f'1 {target_kh.hex()}',
    ]

    assert any('quorum not satisfied' in rec.message for rec in caplog.records)


def test_do_poll_stale_alert_on_quorum_failure(
    state_dir: Path, fake_log: FakeSigsumLog, monkeypatch
):
    witness = FakeWitness('w1')
    fake_log.add_witness(witness)
    (state_dir / 'policy').write_text(
        f'{fake_log.policy_line()}\n'
        f'{witness.policy_line()}\n'
        f'quorum w1\n'
    )

    cli.do_init(_init_args(state_dir, leaf_index=0))
    _make_hook(
        state_dir,
        'log_health',
        'record',
        'echo "$STATE $LAST_SUCCESS_AGE" >> health.log',
    )

    def poll_at(t: int, witness_active: bool, witness_delta: int = 0):
        witness.active = witness_active
        if witness_active:
            witness.time = t - witness_delta
        monkeypatch.setattr(cli.time, 'time', lambda: float(t))
        cli.do_poll(_poll_args(state_dir, max_stale=60))

    def health_lines() -> list[str]:
        log = state_dir / 'health.log'
        return log.read_text().splitlines() if log.exists() else []

    # All good in the beginning
    poll_at(1000, True)
    assert health_lines() == []

    # Witness gone past max_stale
    poll_at(1100, False)
    assert health_lines() == ['failed 100']

    # Failure should not refire
    poll_at(1200, False)
    assert health_lines() == ['failed 100']

    # Witness recovers with delta
    poll_at(1300, True, 10)
    assert health_lines() == ['failed 100', 'okay 10']

    # Further healthy polls must not refire
    poll_at(1400, True)
    assert health_lines() == ['failed 100', 'okay 10']

    # Second stale/recover cycle fires again
    poll_at(1500, False)
    assert health_lines() == ['failed 100', 'okay 10', 'failed 100']

    poll_at(1600, True)
    assert health_lines() == ['failed 100', 'okay 10', 'failed 100', 'okay 0']
