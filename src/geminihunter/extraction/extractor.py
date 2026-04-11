"""API key extraction and deduplication engine."""

import logging

from geminihunter.extraction.patterns import (
    GOOGLE_API_KEY_RE,
    REVERSE_KEY_RE,
    SPLIT_KEY_ARRAY_JOIN,
    SPLIT_KEY_CONCAT,
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

        # Secondary: concatenation patterns
        for match in SPLIT_KEY_CONCAT.finditer(text):
            suffix = match.group(1)
            if len(suffix) == 33:
                found_keys.add(f"AIzaSy{suffix}")

        # Array join patterns
        for match in SPLIT_KEY_ARRAY_JOIN.finditer(text):
            suffix = match.group(1)
            if len(suffix) == 33:
                found_keys.add(f"AIzaSy{suffix}")

        # Reversed key patterns
        for match in REVERSE_KEY_RE.finditer(text):
            reversed_key = match.group(1)[::-1]
            if reversed_key.startswith("AIzaSy"):
                found_keys.add(reversed_key)

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
            else:
                self._seen[key] = ExtractedKey(
                    key=key,
                    sources=[source.url],
                    source_types=[source.source_type],
                    target_domain=source.target_domain,
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
