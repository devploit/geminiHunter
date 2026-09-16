from unittest.mock import AsyncMock

import httpx
import pytest

from geminihunter.config import Config
from geminihunter.network.session import SessionManager


@pytest.mark.asyncio
async def test_retries_are_rate_limited_and_preserve_last_response(monkeypatch):
    session = SessionManager(Config())
    session.rate_limiter.acquire = AsyncMock()
    sleep = AsyncMock()
    monkeypatch.setattr("geminihunter.network.session.asyncio.sleep", sleep)
    client = AsyncMock()
    client.request.return_value = httpx.Response(503)
    response = await session.fetch(client, "https://example.com", max_retries=2)
    assert response.status_code == 503
    assert session.rate_limiter.acquire.await_count == 2
    assert sleep.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("retry_after", ["invalid", "Wed, 01 Jan 2020 00:00:00 GMT", "9999999999", "-1"])
async def test_retry_after_is_bounded_and_tolerates_http_dates(monkeypatch, retry_after):
    session = SessionManager(Config())
    sleep = AsyncMock()
    monkeypatch.setattr("geminihunter.network.session.asyncio.sleep", sleep)
    client = AsyncMock()
    client.request.side_effect = [httpx.Response(429, headers={"Retry-After": retry_after}), httpx.Response(200)]
    response = await session.fetch(client, "https://example.com", max_retries=2)
    assert response.status_code == 200
    assert 0 <= sleep.call_args.args[0] <= 60


@pytest.mark.asyncio
async def test_request_does_not_mutate_callers_headers():
    session = SessionManager(Config())
    client = AsyncMock()
    client.request.return_value = httpx.Response(200)
    headers = {"User-Agent": "explicit-agent", "Referer": "https://example.com"}
    await session.fetch(client, "https://example.com", headers=headers)
    assert headers["User-Agent"] == "explicit-agent"
    assert client.request.call_args.kwargs["headers"]["User-Agent"] == "explicit-agent"
