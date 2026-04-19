import dataclasses

import pytest

from sigmon.monitor import Monitor, LogConsistencyError
from sigmon.sigsum import ConsistencyProof

from fake_log import FakeSigsumLog
from utils import make_leaf

def test_from_empty_log(fake_log: FakeSigsumLog):
    monitor = Monitor.from_log(fake_log)
    assert monitor.tree.size == 0
    assert monitor.tree.stack == []


def test_from_log_tails_single_leaf(fake_log: FakeSigsumLog):
    fake_log.append(make_leaf(0))

    monitor = Monitor.from_log(fake_log)
    assert monitor.tree.size == 1
    assert monitor.tree.root_hash() == fake_log.get_tree_head().root_hash


def test_from_log_tails_existing_log(fake_log: FakeSigsumLog):
    for i in range(5):
        fake_log.append(make_leaf(i))

    monitor = Monitor.from_log(fake_log)
    assert monitor.tree.size == 5
    assert monitor.tree.root_hash() == fake_log.get_tree_head().root_hash


def test_from_log_rejects_start_index_past_size(fake_log: FakeSigsumLog):
    for i in range(3):
        fake_log.append(make_leaf(i))

    with pytest.raises(ValueError, match='exceeds current tree size'):
        Monitor.from_log(fake_log, start_index=3)


def test_poll_no_advance(fake_log: FakeSigsumLog):
    fake_log.append(make_leaf(0))
    monitor = Monitor.from_log(fake_log)

    th, start, leaves, remaining = monitor.poll()
    assert th.size == 1
    assert start == 1
    assert leaves == []
    assert remaining == 0


def test_poll_incremental_growth(fake_log: FakeSigsumLog):
    monitor = Monitor.from_log(fake_log, start_index=0)

    total = 0
    for batch in [3, 1, 7, 2, 5]:
        batch_leaves = [make_leaf(total + i) for i in range(batch)]
        for leaf in batch_leaves:
            fake_log.append(leaf)

        th, start, leaves, remaining = monitor.poll()
        assert th.size == total + batch
        assert start == total
        assert leaves == batch_leaves
        assert remaining == 0
        assert monitor.tree.root_hash() == th.root_hash

        total += batch


def test_poll_batched_returns_expected_leaves(fake_log: FakeSigsumLog):
    monitor = Monitor.from_log(fake_log, start_index=0)

    expected = [make_leaf(i) for i in range(10)]
    for leaf in expected:
        fake_log.append(leaf)

    _, start, leaves, remaining = monitor.poll(batch_size=4)
    assert start == 0
    assert leaves == expected[:4]
    assert remaining == 6

    _, start, leaves, remaining = monitor.poll(batch_size=4)
    assert start == 4
    assert leaves == expected[4:8]
    assert remaining == 2

    _, start, leaves, remaining = monitor.poll(batch_size=4)
    assert start == 8
    assert leaves == expected[8:]
    assert remaining == 0


def test_poll_rejects_root_hash_mismatch(fake_log: FakeSigsumLog, monkeypatch):
    monitor = Monitor.from_log(fake_log, start_index=0)

    for i in range(4):
        fake_log.append(make_leaf(i))

    original = fake_log.get_tree_head

    def bad_head():
        th = original()
        return dataclasses.replace(th, root_hash=b'\xff' * 32)

    monkeypatch.setattr(fake_log, 'get_tree_head', bad_head)

    with pytest.raises(LogConsistencyError, match='root hash mismatch'):
        monitor.poll()


def test_poll_rejects_bad_consistency_proof(fake_log: FakeSigsumLog, monkeypatch):
    monitor = Monitor.from_log(fake_log, start_index=0)
    for i in range(5):
        fake_log.append(make_leaf(i))

    monkeypatch.setattr(
        fake_log,
        'get_consistency_proof',
        lambda old, new: ConsistencyProof([b'\x00' * 32], old, new),
    )

    with pytest.raises(LogConsistencyError, match='consistency proof is invalid'):
        monitor.poll(batch_size=2)


def test_state_roundtrip(fake_log: FakeSigsumLog):
    for i in range(7):
        fake_log.append(make_leaf(i))
    monitor = Monitor.from_log(fake_log, start_index=0)
    monitor.poll()

    state = monitor.get_state()
    restored = Monitor.from_state(fake_log, state)
    assert restored.tree.size == monitor.tree.size
    assert restored.tree.stack == monitor.tree.stack

    fake_log.append(make_leaf(7))
    th, _, _, _ = restored.poll()
    assert restored.tree.root_hash() == th.root_hash
