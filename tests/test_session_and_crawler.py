import pytest

from geminihunter.config import Config
from geminihunter.discovery.crawler import Crawler
from geminihunter.network.session import SessionManager
from geminihunter.network.transport import TransportIssue


@pytest.mark.asyncio
async def test_session_skips_non_retryable_host_failures():
    config = Config()
    session = SessionManager(config)
    session._host_failures[("https", "example.com")] = TransportIssue(
        kind="tls",
        detail="hostname mismatch",
        retryable=False,
    )

    class Client:
        async def request(self, *args, **kwargs):  # pragma: no cover
            raise AssertionError("request should not be called")

    resp = await session.fetch(Client(), "https://example.com/app.js")
    assert resp is None


@pytest.mark.asyncio
async def test_crawler_falls_back_to_http_after_tls_failure():
    class FakeResponse:
        def __init__(self, text, content_type="text/html", status_code=200):
            self.text = text
            self.status_code = status_code
            self.headers = {"content-type": content_type}

    class FakeSession:
        def __init__(self):
            self.calls = []
            self.issue = TransportIssue("tls", "hostname mismatch", False)

        async def fetch(self, client, url, headers=None):
            self.calls.append(url)
            if url.startswith("https://"):
                return None
            return FakeResponse('<script src="/app.js"></script>')

        def should_try_http_fallback(self, url):
            return url.startswith("https://")

    crawler = Crawler(client=object(), config=Config(depth=0), session=FakeSession())
    sources = await crawler.crawl("example.com")

    assert any(url.startswith("http://example.com") for url in crawler.session.calls)
    assert sources
