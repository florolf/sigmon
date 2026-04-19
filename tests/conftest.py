import pytest

from sigmon import cli
from fake_log import FakeSigsumLog

@pytest.fixture
def fake_log(monkeypatch) -> FakeSigsumLog:
    log = FakeSigsumLog('fake')

    class _StubAPI:
        @staticmethod
        def from_policy(policy_text, log_filter=None):
            del policy_text, log_filter
            return log

    monkeypatch.setattr(cli, 'SigsumLogAPI', _StubAPI)

    return log


@pytest.fixture
def state_dir(tmp_path, fake_log):
    policy = (
        f'{fake_log.policy_line()}\n'
        f'quorum none\n'
    )
    (tmp_path / 'policy').write_text(policy)
    (tmp_path / 'watchlist').write_text('')

    return tmp_path
