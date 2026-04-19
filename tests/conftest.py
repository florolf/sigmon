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
