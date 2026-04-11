"""Key validation orchestrator."""

import asyncio
import logging

import httpx

from geminihunter.config import Config
from geminihunter.models import ExtractedKey, KeyStatus, ValidatedKey
from geminihunter.validation.bypass import GEMINI_BASE_URL, BypassEngine

logger = logging.getLogger("geminihunter")


class KeyValidator:
    """Validates API keys against the Google Gemini API."""

    def __init__(self, client: httpx.AsyncClient, config: Config):
        self.client = client
        self.config = config
        self.bypass_engine = BypassEngine()

    async def validate_all(self, keys: list[ExtractedKey]) -> list[ValidatedKey]:
        """Validate all extracted keys with concurrency control."""
        sem = asyncio.Semaphore(self.config.concurrency)
        tasks = [self._validate_one(k, sem) for k in keys]
        results = await asyncio.gather(*tasks)
        return list(results)

    async def _validate_one(
        self, key: ExtractedKey, sem: asyncio.Semaphore
    ) -> ValidatedKey:
        """Validate a single key."""
        async with sem:
            url = f"{GEMINI_BASE_URL}/v1beta/models?key={key.key}"

            try:
                resp = await self.client.get(url, timeout=self.config.timeout)
            except (httpx.HTTPError, Exception) as e:
                logger.debug(f"Validation error for ...{key.key[-8:]}: {e}")
                return ValidatedKey(
                    key=key.key,
                    status=KeyStatus.UNKNOWN,
                    initial_status_code=0,
                    target_domain=key.target_domain,
                    sources=key.sources,
                )

            status_code = resp.status_code

            if status_code == 200:
                return ValidatedKey(
                    key=key.key,
                    status=KeyStatus.VALID,
                    initial_status_code=status_code,
                    target_domain=key.target_domain,
                    sources=key.sources,
                    raw_response=resp.text,
                )

            if status_code == 403 and self.config.bypass:
                bypass_result = await self.bypass_engine.run(
                    key.key,
                    key.target_domain,
                    self.client,
                    concurrency=min(5, self.config.concurrency),
                )
                if bypass_result:
                    return ValidatedKey(
                        key=key.key,
                        status=KeyStatus.BYPASSED,
                        initial_status_code=status_code,
                        target_domain=key.target_domain,
                        sources=key.sources,
                        bypass=bypass_result,
                    )
                return ValidatedKey(
                    key=key.key,
                    status=KeyStatus.FORBIDDEN,
                    initial_status_code=status_code,
                    target_domain=key.target_domain,
                    sources=key.sources,
                )

            if status_code == 403:
                return ValidatedKey(
                    key=key.key,
                    status=KeyStatus.FORBIDDEN,
                    initial_status_code=status_code,
                    target_domain=key.target_domain,
                    sources=key.sources,
                )

            return ValidatedKey(
                key=key.key,
                status=KeyStatus.INVALID,
                initial_status_code=status_code,
                target_domain=key.target_domain,
                sources=key.sources,
            )
