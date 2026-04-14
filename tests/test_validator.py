from types import SimpleNamespace

import pytest

from geminihunter.config import Config
from geminihunter.models import BypassDetail, ExtractedKey, KeyStatus, SourceType
from geminihunter.validation.validator import KeyValidator


class DummyResponse:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text
        self.headers = {}


@pytest.mark.asyncio
async def test_validator_revalidates_429_bypass(monkeypatch):
    calls = iter(
        [
            DummyResponse(403, "forbidden"),
            DummyResponse(200, "ok"),
        ]
    )

    class FakeSession:
        async def fetch(self, *args, **kwargs):
            return next(calls)

        def get_last_issue(self, url):
            return None

    validator = KeyValidator(client=object(), config=Config(), session=FakeSession())

    async def fake_run(*args, **kwargs):
        return BypassDetail(
            technique="test",
            headers={},
            api_version="v1beta",
            endpoint="models",
            method="GET",
            bypass_status_code=429,
            key_in_header=False,
        )

    validator.bypass_engine = SimpleNamespace(run=fake_run)

    result = await validator.validate_all(
        [
            ExtractedKey(
                key="AIzaSy123456789012345678901234567890123",
                sources=["https://example.com/app.js"],
                source_types=[SourceType.JS_FILE],
                target_domain="example.com",
                target_domains=["example.com"],
            )
        ]
    )

    assert result[0].status == KeyStatus.BYPASSED
    assert result[0].bypass is not None
    assert result[0].bypass.bypass_status_code == 200
