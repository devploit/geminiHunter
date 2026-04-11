"""Key intelligence gathering -- models, billing, quota, project ID."""

import asyncio
import json
import logging

import httpx

from geminihunter.config import Config
from geminihunter.models import KeyIntelligence, KeyStatus, ValidatedKey
from geminihunter.validation.bypass import GEMINI_BASE_URL

logger = logging.getLogger("geminihunter")


class KeyRecon:
    """Gathers intelligence on working (valid/bypassed) API keys."""

    def __init__(self, client: httpx.AsyncClient, config: Config):
        self.client = client
        self.config = config

    async def gather_all(self, keys: list[ValidatedKey]) -> list[KeyIntelligence]:
        """Gather intelligence on all working keys."""
        sem = asyncio.Semaphore(self.config.concurrency)

        async def recon_with_sem(key: ValidatedKey) -> KeyIntelligence:
            async with sem:
                return await self._recon_one(key)

        tasks = [recon_with_sem(k) for k in keys]
        return list(await asyncio.gather(*tasks))

    async def _recon_one(self, key: ValidatedKey) -> KeyIntelligence:
        """Gather intelligence on a single key."""
        # Build headers for bypassed keys
        headers: dict[str, str] = {}
        api_version = "v1beta"
        if key.bypass:
            headers = dict(key.bypass.headers)
            api_version = key.bypass.api_version

        intel = KeyIntelligence(
            key=key.key,
            status=key.status,
            target_domain=key.target_domain,
            sources=key.sources,
            bypass=key.bypass,
        )

        # Run intelligence probes concurrently
        results = await asyncio.gather(
            self._list_models(key.key, headers, api_version),
            self._extract_project_id(key.key, headers, api_version),
            self._check_billing(key.key, headers, api_version),
            return_exceptions=True,
        )

        if isinstance(results[0], list):
            intel.available_models = results[0]
        if isinstance(results[1], str):
            intel.project_id = results[1]
        if isinstance(results[2], tuple):
            intel.billing_enabled, intel.quota_remaining, intel.quota_limit = results[2]

        return intel

    async def _list_models(
        self, key: str, headers: dict[str, str], api_version: str
    ) -> list[str]:
        """List all available models for this key."""
        url = f"{GEMINI_BASE_URL}/{api_version}/models?key={key}"
        try:
            resp = await self.client.get(url, headers=headers, timeout=self.config.timeout)
            if resp.status_code != 200:
                return []

            data = resp.json()
            models = []
            for model in data.get("models", []):
                name = model.get("name", "")
                if name.startswith("models/"):
                    name = name[7:]
                models.append(name)
            return sorted(models)

        except (httpx.HTTPError, ValueError, KeyError) as e:
            logger.debug(f"Failed to list models: {e}")
            return []

    async def _extract_project_id(
        self, key: str, headers: dict[str, str], api_version: str
    ) -> str | None:
        """
        Try to extract the GCP project ID from API responses.

        Google often includes project info in error messages or response headers.
        """
        # Method 1: Try an intentionally bad request that leaks project info
        url = f"{GEMINI_BASE_URL}/{api_version}/models/nonexistent-model?key={key}"
        try:
            resp = await self.client.get(url, headers=headers, timeout=self.config.timeout)
            text = resp.text

            # Look for project number in error response
            import re

            project_match = re.search(r'"project"\s*:\s*"(\d+)"', text)
            if project_match:
                return project_match.group(1)

            project_match = re.search(r'project[_\s](?:id|number)["\s:]+(\d+)', text, re.IGNORECASE)
            if project_match:
                return project_match.group(1)

            # Check response headers for project info
            for header_name in ["x-goog-project-id", "x-goog-project-number"]:
                if header_name in resp.headers:
                    return resp.headers[header_name]

        except (httpx.HTTPError, Exception) as e:
            logger.debug(f"Failed to extract project ID: {e}")

        return None

    async def _check_billing(
        self, key: str, headers: dict[str, str], api_version: str
    ) -> tuple[bool | None, int | None, int | None]:
        """
        Probe billing status by attempting a generation request.

        If the key can generate content, billing is likely active.
        Also extracts quota info from response headers.
        """
        url = f"{GEMINI_BASE_URL}/{api_version}/models/gemini-2.0-flash:generateContent?key={key}"
        body = json.dumps(
            {"contents": [{"parts": [{"text": "Say 'test' and nothing else."}]}]}
        )
        req_headers = {**headers, "Content-Type": "application/json"}

        try:
            resp = await self.client.post(
                url, content=body, headers=req_headers, timeout=self.config.timeout
            )

            billing_enabled = None
            quota_remaining = None
            quota_limit = None

            if resp.status_code == 200:
                billing_enabled = True
            elif resp.status_code == 429:
                # Rate limited but key works -- billing is active, just quota exhausted
                billing_enabled = True
            elif resp.status_code == 403:
                text = resp.text
                if "BILLING" in text.upper() or "billing" in text:
                    billing_enabled = False
                elif "QUOTA" in text.upper():
                    billing_enabled = True  # Has billing, just out of quota

            # Check quota headers
            for header in resp.headers:
                h_lower = header.lower()
                if "quota" in h_lower and "remaining" in h_lower:
                    try:
                        quota_remaining = int(resp.headers[header])
                    except ValueError:
                        pass
                if "quota" in h_lower and "limit" in h_lower:
                    try:
                        quota_limit = int(resp.headers[header])
                    except ValueError:
                        pass

            return billing_enabled, quota_remaining, quota_limit

        except (httpx.HTTPError, Exception) as e:
            logger.debug(f"Failed to check billing: {e}")
            return None, None, None
