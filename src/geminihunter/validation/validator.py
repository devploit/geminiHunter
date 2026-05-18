"""Key validation orchestrator."""

import asyncio
import logging

import httpx

from geminihunter.config import Config
from geminihunter.models import ExtractedKey, KeyStatus, ValidatedKey
from geminihunter.network.session import SessionManager
from geminihunter.validation.bypass import (
    GEMINI_BASE_URL,
    BypassEngine,
    google_error_reason,
)

logger = logging.getLogger("geminihunter")


class KeyValidator:
    """Validates API keys against the Google Gemini API."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        config: Config,
        session: SessionManager,
    ):
        self.client = client
        self.config = config
        self.session = session
        self.bypass_engine = BypassEngine()

    async def _confirm_rate_limited_bypass(
        self,
        key: str,
        bypass,
    ) -> bool:
        """Revalidate 429 bypasses with a short backoff before treating them as success."""
        headers = dict(bypass.headers)
        url = f"{GEMINI_BASE_URL}/{bypass.api_version}/{bypass.endpoint}"
        if not bypass.key_in_header:
            url = f"{url}?key={key}"
        else:
            headers["x-goog-api-key"] = key

        for delay in (0.25, 0.75):
            await asyncio.sleep(delay)
            resp = await self.session.fetch(
                self.client,
                url,
                method=bypass.method,
                headers=headers,
                data=bypass.body,
                timeout=min(5.0, self.config.timeout),
                max_retries=1,
                retry_on_429=False,
            )
            if resp is not None and resp.status_code == 200:
                bypass.bypass_status_code = 200
                return True
        return False

    @staticmethod
    def _detail_from_response(resp: httpx.Response) -> str | None:
        reason = google_error_reason(resp)
        text = resp.text.lower()
        if resp.status_code == 403:
            if reason == "SERVICE_DISABLED":
                return "403 service disabled"
            if reason == "API_KEY_HTTP_REFERRER_BLOCKED":
                return "403 referrer restriction"
            if "billing" in text:
                return "403 billing disabled"
            if "quota" in text:
                return "403 quota-related restriction"
            if "referer" in text or "referrer" in text:
                return "403 referrer restriction"
            if "api key not valid" in text or "invalid api key" in text:
                return "403 invalid API key"
            return "403 forbidden"
        if resp.status_code == 429:
            return "429 accepted but rate-limited"
        return None

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
                resp = await self.session.fetch(
                    self.client,
                    url,
                    retry_on_429=False,
                )
            except (httpx.HTTPError, Exception) as e:
                logger.debug(f"Validation error for ...{key.key[-8:]}: {e}")
                return ValidatedKey(
                    key=key.key,
                    status=KeyStatus.UNKNOWN,
                    initial_status_code=0,
                    target_domain=key.target_domain,
                    sources=key.sources,
                )

            if resp is None:
                issue = self.session.get_last_issue(url)
                return ValidatedKey(
                    key=key.key,
                    status=KeyStatus.UNKNOWN,
                    initial_status_code=0,
                    target_domain=key.target_domain,
                    sources=key.sources,
                    detail=issue.detail if issue else "no response",
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
                initial_reason = google_error_reason(resp)
                candidate_domains = key.target_domains or [key.target_domain]
                seen_domains: set[str] = set()
                for candidate_domain in candidate_domains:
                    if candidate_domain in seen_domains:
                        continue
                    seen_domains.add(candidate_domain)
                    bypass_result = await self.bypass_engine.run(
                        key.key,
                        candidate_domain,
                        self.client,
                        self.session,
                        source_urls=key.sources,
                        target_domains=key.target_domains,
                        concurrency=10,
                        initial_reason=initial_reason,
                    )
                    if bypass_result:
                        if bypass_result.bypass_status_code == 403:
                            detail = (
                                "referrer restriction passed, but Gemini API is disabled"
                                if bypass_result.error_reason == "SERVICE_DISABLED"
                                else "permission changed after bypass attempt"
                            )
                            return ValidatedKey(
                                key=key.key,
                                status=KeyStatus.FORBIDDEN,
                                initial_status_code=status_code,
                                target_domain=candidate_domain,
                                sources=key.sources,
                                bypass=bypass_result,
                                detail=detail,
                            )
                        bypass_status = KeyStatus.BYPASSED
                        detail = None
                        if bypass_result.bypass_status_code == 429:
                            confirmed = await self._confirm_rate_limited_bypass(
                                key.key,
                                bypass_result,
                            )
                            if not confirmed:
                                bypass_status = KeyStatus.RATE_LIMITED
                                detail = "accepted but rate-limited"
                        return ValidatedKey(
                            key=key.key,
                            status=bypass_status,
                            initial_status_code=status_code,
                            target_domain=candidate_domain,
                            sources=key.sources,
                            bypass=bypass_result,
                            detail=detail,
                        )
                return ValidatedKey(
                    key=key.key,
                    status=KeyStatus.FORBIDDEN,
                    initial_status_code=status_code,
                    target_domain=key.target_domain,
                    sources=key.sources,
                    detail="403 forbidden after bypass attempts",
                )

            if status_code == 403:
                return ValidatedKey(
                    key=key.key,
                    status=KeyStatus.FORBIDDEN,
                    initial_status_code=status_code,
                    target_domain=key.target_domain,
                    sources=key.sources,
                    detail=self._detail_from_response(resp),
                )

            if status_code == 429:
                return ValidatedKey(
                    key=key.key,
                    status=KeyStatus.RATE_LIMITED,
                    initial_status_code=status_code,
                    target_domain=key.target_domain,
                    sources=key.sources,
                    detail=self._detail_from_response(resp),
                )

            return ValidatedKey(
                key=key.key,
                status=KeyStatus.INVALID,
                initial_status_code=status_code,
                target_domain=key.target_domain,
                sources=key.sources,
                detail=self._detail_from_response(resp) or f"unexpected status {status_code}",
            )
