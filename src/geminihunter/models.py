"""Data models for the GeminiHunter pipeline."""

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    HTML_INLINE = "html_inline"
    JS_FILE = "js_file"
    JS_MAP = "js_map"
    WAYBACK_JS = "wayback_js"
    WEBPACK_CHUNK = "webpack_chunk"
    DIRECT_INPUT = "direct_input"


class KeyStatus(str, Enum):
    VALID = "valid"
    FORBIDDEN = "forbidden"
    BYPASSED = "bypassed"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class DiscoveredSource(BaseModel):
    """A URL that was fetched and may contain API keys."""

    url: str
    source_type: SourceType
    target_domain: str
    content: str = Field(exclude=True, repr=False)
    fetched_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class ExtractedKey(BaseModel):
    """A unique API key found in one or more sources."""

    key: str
    sources: list[str] = Field(default_factory=list)
    source_types: list[SourceType] = Field(default_factory=list)
    target_domain: str = ""
    first_seen_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class BypassDetail(BaseModel):
    """Details of a successful bypass attempt."""

    technique: str
    headers: dict[str, str] = Field(default_factory=dict)
    api_version: str = "v1beta"
    endpoint: str = "models"
    method: str = "GET"
    curl_command: str = ""


class ValidatedKey(BaseModel):
    """A key after validation (and optional bypass)."""

    key: str
    status: KeyStatus
    initial_status_code: int = 0
    target_domain: str = ""
    sources: list[str] = Field(default_factory=list)
    bypass: BypassDetail | None = None
    raw_response: str = Field(default="", exclude=True)


class KeyIntelligence(BaseModel):
    """Full intelligence gathered on a working key."""

    key: str
    status: KeyStatus
    target_domain: str = ""
    sources: list[str] = Field(default_factory=list)
    bypass: BypassDetail | None = None

    # Intelligence fields
    available_models: list[str] = Field(default_factory=list)
    project_id: str | None = None
    billing_enabled: bool | None = None
    quota_remaining: int | None = None
    quota_limit: int | None = None

    # Evidence
    curl_commands: list[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Top-level result of a full scan."""

    targets_scanned: list[str] = Field(default_factory=list)
    sources_crawled: int = 0
    keys_found: int = 0
    keys_valid: int = 0
    keys_bypassed: int = 0
    keys_forbidden: int = 0
    keys_invalid: int = 0
    duration_seconds: float = 0.0
    results: list[KeyIntelligence] = Field(default_factory=list)
