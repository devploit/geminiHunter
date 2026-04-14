"""API key extraction and deduplication engine."""

import base64
import logging
import re

from geminihunter.extraction.patterns import (
    BASE64_KEY_RE,
    CONCAT_PART_RE,
    FALLBACK_KEY_RE,
    GOOGLE_API_KEY_RE,
    HEX_PREFIX_RE,
    MULTILINE_CONCAT_RE,
    REVERSE_KEY_RE,
    SPLIT_KEY_ARRAY_JOIN,
    SPLIT_KEY_CONCAT,
    SPLIT_KEY_TEMPLATE,
)
from geminihunter.models import DiscoveredSource, ExtractedKey

logger = logging.getLogger("geminihunter")


class KeyExtractor:
    """Extracts and deduplicates Google API keys from sources."""

    def __init__(self):
        self._seen: dict[str, ExtractedKey] = {}

    def extract_from_source(
        self, source: DiscoveredSource, content: str | None = None
    ) -> list[str]:
        """
        Extract keys from a single source.

        Args:
            source: The discovered source metadata.
            content: Processed content (e.g., deobfuscated). Falls back to source.content.

        Returns:
            List of newly discovered key strings (not seen before).
        """
        text = content if content is not None else source.content
        found_keys: set[str] = set()

        # Primary: direct regex match
        found_keys.update(GOOGLE_API_KEY_RE.findall(text))

        # Concatenation: "AIzaSy" + "suffix"
        for match in SPLIT_KEY_CONCAT.finditer(text):
            suffix = match.group(1)
            if len(suffix) == 33:
                found_keys.add(f"AIzaSy{suffix}")

        # Array join: ["AIzaSy","rest"].join("")
        for match in SPLIT_KEY_ARRAY_JOIN.finditer(text):
            suffix = match.group(1)
            if len(suffix) == 33:
                found_keys.add(f"AIzaSy{suffix}")

        # Reversed keys
        for match in REVERSE_KEY_RE.finditer(text):
            reversed_key = match.group(1)[::-1]
            if reversed_key.startswith("AIzaSy"):
                found_keys.add(reversed_key)

        # Template literal: `AIzaSy${expr}` -- extract only when expr is a literal value
        for match in SPLIT_KEY_TEMPLATE.finditer(text):
            inner = match.group(1).strip().strip("\"'")
            if re.fullmatch(r"[a-zA-Z0-9_-]{33}", inner):
                found_keys.add(f"AIzaSy{inner}")

        # Multi-part concatenation: "AIzaSy" + "p1" + "p2" + ...
        for match in MULTILINE_CONCAT_RE.finditer(text):
            parts = CONCAT_PART_RE.findall(match.group(0))
            if parts and parts[0] == "AIzaSy":
                suffix = "".join(parts[1:])
                if len(suffix) == 33:
                    found_keys.add(f"AIzaSy{suffix}")

        # Fallback/default values: || "AIzaSy..."
        found_keys.update(FALLBACK_KEY_RE.findall(text))

        # Hex-encoded prefix: \x41\x49\x7a\x61\x53\x79 + plain suffix
        for match in HEX_PREFIX_RE.finditer(text):
            found_keys.add(f"AIzaSy{match.group(1)}")

        # Base64-encoded keys: "QUl6YVN5..." -> decode -> "AIzaSy..."
        for match in BASE64_KEY_RE.finditer(text):
            try:
                b64str = match.group(1).replace("-", "+").replace("_", "/")
                decoded = base64.b64decode(b64str).decode("ascii")
                if decoded.startswith("AIzaSy"):
                    found_keys.add(decoded)
            except Exception:
                pass

        # Dedup against global state
        new_keys: list[str] = []
        for key in found_keys:
            if not self._is_valid_key_format(key):
                continue

            if key in self._seen:
                existing = self._seen[key]
                if source.url not in existing.sources:
                    existing.sources.append(source.url)
                if source.source_type not in existing.source_types:
                    existing.source_types.append(source.source_type)
                if (
                    source.target_domain
                    and source.target_domain not in existing.target_domains
                ):
                    existing.target_domains.append(source.target_domain)
            else:
                self._seen[key] = ExtractedKey(
                    key=key,
                    sources=[source.url],
                    source_types=[source.source_type],
                    target_domain=source.target_domain,
                    target_domains=[source.target_domain] if source.target_domain else [],
                )
                new_keys.append(key)

        if new_keys:
            logger.info(f"Found {len(new_keys)} new key(s) in {source.url}")

        return new_keys

    @staticmethod
    def _is_valid_key_format(key: str) -> bool:
        """Basic format validation to filter false positives."""
        if len(key) != 39:
            return False
        if not key.startswith("AIzaSy"):
            return False
        # Reject keys that are all the same character after prefix (likely placeholder)
        suffix = key[6:]
        if len(set(suffix)) < 5:
            return False
        return True

    @property
    def all_keys(self) -> list[ExtractedKey]:
        return list(self._seen.values())

    @property
    def count(self) -> int:
        return len(self._seen)
