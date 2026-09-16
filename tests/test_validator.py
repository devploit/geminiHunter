from types import SimpleNamespace

import pytest

from geminihunter.config import Config
from geminihunter.models import BypassDetail, ExtractedKey, KeyStatus, SourceType
from geminihunter.validation.validator import KeyValidator


class DummyResponse:
    def __init__(self, status_code, text="", json_data=None):
        self.status_code = status_code
        self.text = text
        self.headers = {}
        self._json_data = json_data

    def json(self):
        if self._json_data is None:
            raise ValueError("no json")
        return self._json_data


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
                key="synthetic-key",
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


@pytest.mark.asyncio
async def test_validator_reports_referrer_progress_when_service_disabled():
    initial_403 = {
        "error": {
            "details": [
                {
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "API_KEY_HTTP_REFERRER_BLOCKED",
                }
            ]
        }
    }

    class FakeSession:
        async def fetch(self, *args, **kwargs):
            return DummyResponse(403, "referer blocked", initial_403)

        def get_last_issue(self, url):
            return None

    validator = KeyValidator(client=object(), config=Config(), session=FakeSession())

    async def fake_run(*args, **kwargs):
        assert kwargs["initial_reason"] == "API_KEY_HTTP_REFERRER_BLOCKED"
        return BypassDetail(
            technique="common-referer:files:127.0.0.1",
            headers={"Referer": "127.0.0.1"},
            api_version="v1beta",
            endpoint="files",
            method="GET",
            bypass_status_code=403,
            key_in_header=False,
            error_reason="SERVICE_DISABLED",
        )

    validator.bypass_engine = SimpleNamespace(run=fake_run)

    result = await validator.validate_all(
        [
            ExtractedKey(
                key="synthetic-key",
                sources=["https://example.com/app.js"],
                source_types=[SourceType.JS_FILE],
                target_domain="example.com",
                target_domains=["example.com"],
            )
        ]
    )

    assert result[0].status == KeyStatus.FORBIDDEN
    assert result[0].bypass is not None
    assert result[0].bypass.error_reason == "SERVICE_DISABLED"
    assert result[0].detail == "referrer restriction passed, but Gemini API is disabled"


@pytest.mark.asyncio
async def test_validator_runs_bypass_once_with_all_candidate_domains():
    class FakeSession:
        async def fetch(self, *args, **kwargs):
            return DummyResponse(403, "forbidden")

        def get_last_issue(self, url):
            return None

    validator = KeyValidator(client=object(), config=Config(), session=FakeSession())
    calls = []

    async def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return None

    validator.bypass_engine = SimpleNamespace(run=fake_run)

    result = await validator.validate_all(
        [
            ExtractedKey(
                key="synthetic-key",
                sources=["https://a.example.com/app.js"],
                source_types=[SourceType.JS_FILE],
                target_domain="example.com",
                target_domains=["a.example.com", "b.example.com", "example.com"],
            )
        ]
    )

    assert len(calls) == 1
    assert calls[0][0][1] == "a.example.com"
    assert calls[0][1]["target_domains"] == [
        "a.example.com",
        "b.example.com",
        "example.com",
    ]
    assert result[0].status == KeyStatus.FORBIDDEN


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [301, 404, 500, 503])
async def test_unexpected_endpoint_response_is_not_an_invalid_key(status):
    class FakeSession:
        async def fetch(self, *args, **kwargs):
            return DummyResponse(status)

    validator = KeyValidator(object(), Config(bypass=False), FakeSession())
    results = await validator.validate_all([ExtractedKey(key="synthetic-key")])
    assert results[0].status == KeyStatus.UNKNOWN
