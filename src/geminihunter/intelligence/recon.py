"""Key intelligence gathering -- models, billing, quota, project ID."""

import asyncio
import json
import logging
import re

import httpx

from geminihunter.config import Config
from geminihunter.models import KeyIntelligence, KeyRestrictions, KeyStatus, ValidatedKey
from geminihunter.network.session import SessionManager
from geminihunter.validation.bypass import GEMINI_BASE_URL, google_error_reason

logger = logging.getLogger("geminihunter")


class KeyRecon:
    """Gathers intelligence on working (valid/bypassed) API keys."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        config: Config,
        session: SessionManager,
    ):
        self.client = client
        self.config = config
        self.session = session

    async def gather_all(self, keys: list[ValidatedKey]) -> list[KeyIntelligence]:
        """Gather intelligence on all working keys."""
        sem = asyncio.Semaphore(self.config.concurrency)

        async def recon_with_sem(key: ValidatedKey) -> KeyIntelligence:
            async with sem:
                return await self._recon_one(key)

        tasks = [recon_with_sem(k) for k in keys]
        return list(await asyncio.gather(*tasks))

    def _build_url(
        self, path: str, key: str, api_version: str, key_in_header: bool
    ) -> str:
        """Build API URL, omitting ?key= when authentication is via header."""
        url = f"{GEMINI_BASE_URL}/{api_version}/{path}"
        if not key_in_header:
            url += f"?key={key}"
        return url

    async def _recon_one(self, key: ValidatedKey) -> KeyIntelligence:
        """Gather intelligence on a single key."""
        # Build headers for bypassed keys
        headers: dict[str, str] = {}
        api_version = "v1beta"
        key_in_header = False
        if key.bypass:
            headers = dict(key.bypass.headers)
            api_version = key.bypass.api_version
            key_in_header = key.bypass.key_in_header

        intel = KeyIntelligence(
            key=key.key,
            status=key.status,
            target_domain=key.target_domain,
            sources=key.sources,
            bypass=key.bypass,
        )

        # Run intelligence probes concurrently
        results = await asyncio.gather(
            self._list_models(key.key, headers, api_version, key_in_header),
            self._list_tuned_models(key.key, headers, api_version, key_in_header),
            self._extract_project_id(key.key, headers, api_version, key_in_header),
            self._check_billing(key.key, headers, api_version, key_in_header),
            self._detect_restrictions(key),
            return_exceptions=True,
        )

        if isinstance(results[0], list):
            intel.available_models = results[0]
        if isinstance(results[1], list):
            intel.tuned_models = results[1]
        if isinstance(results[2], tuple):
            intel.project_id, intel.project_name = results[2]
        elif isinstance(results[2], str):
            intel.project_id = results[2]
        if isinstance(results[3], tuple):
            intel.billing_enabled, intel.quota_remaining, intel.quota_limit = results[3]
        if isinstance(results[4], KeyRestrictions):
            intel.restrictions = results[4]

        return intel

    async def _list_models(
        self,
        key: str,
        headers: dict[str, str],
        api_version: str,
        key_in_header: bool,
    ) -> list[str]:
        """List all available models for this key."""
        url = self._build_url("models", key, api_version, key_in_header)
        try:
            resp = await self.session.fetch(
                self.client,
                url,
                headers=headers,
                retry_on_429=False,
            )
            if resp is None or resp.status_code != 200:
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

    async def _list_tuned_models(
        self,
        key: str,
        headers: dict[str, str],
        api_version: str,
        key_in_header: bool,
    ) -> list[str]:
        """List tuned (fine-tuned) models -- indicates custom training data."""
        url = self._build_url("tunedModels", key, api_version, key_in_header)
        try:
            resp = await self.session.fetch(
                self.client,
                url,
                headers=headers,
                retry_on_429=False,
            )
            if resp is None or resp.status_code != 200:
                return []

            data = resp.json()
            tuned = []
            for model in data.get("tunedModels", []):
                name = model.get("name", "")
                display = model.get("displayName", name)
                tuned.append(display or name)
            return sorted(tuned)

        except (httpx.HTTPError, ValueError, KeyError) as e:
            logger.debug(f"Failed to list tuned models: {e}")
            return []

    async def _extract_project_id(
        self,
        key: str,
        headers: dict[str, str],
        api_version: str,
        key_in_header: bool,
    ) -> tuple[str | None, str | None]:
        """
        Try to extract the GCP project ID and name from API responses.

        Google often includes project info in error messages or response headers.
        """
        project_id: str | None = None
        project_name: str | None = None

        # Method 1: Try an intentionally bad request that leaks project info
        url = self._build_url(
            "models/nonexistent-model", key, api_version, key_in_header
        )
        try:
            resp = await self.session.fetch(
                self.client,
                url,
                headers=headers,
                retry_on_429=False,
            )
            if resp is None:
                return project_id, project_name
            text = resp.text

            # Look for project number in error response
            project_match = re.search(r'"project"\s*:\s*"(\d+)"', text)
            if project_match:
                project_id = project_match.group(1)

            if not project_id:
                project_match = re.search(
                    r'project[_\s](?:id|number)["\s:]+(\d+)', text, re.IGNORECASE
                )
                if project_match:
                    project_id = project_match.group(1)

            # Check response headers for project info
            for header_name in ("x-goog-project-id", "x-goog-project-number"):
                if header_name in resp.headers:
                    project_id = project_id or resp.headers[header_name]

            # Try to extract project name from x-goog-api-resource-name header
            resource_name = resp.headers.get("x-goog-api-resource-name", "")
            if resource_name:
                # Format: projects/{project}/...
                rn_match = re.search(r"projects/([^/]+)", resource_name)
                if rn_match:
                    val = rn_match.group(1)
                    if val.isdigit():
                        project_id = project_id or val
                    else:
                        project_name = val

        except (httpx.HTTPError, Exception) as e:
            logger.debug(f"Failed to extract project ID: {e}")

        return project_id, project_name

    async def _check_billing(
        self,
        key: str,
        headers: dict[str, str],
        api_version: str,
        key_in_header: bool,
    ) -> tuple[bool | None, int | None, int | None]:
        """
        Probe billing status by attempting a generation request.

        Generation can use free quota, so success does not prove paid billing.
        Only report disabled billing when the API explicitly identifies it.
        Also extracts quota info from response headers.
        """
        url = self._build_url(
            "models/gemini-2.0-flash:generateContent",
            key,
            api_version,
            key_in_header,
        )
        body = json.dumps(
            {"contents": [{"parts": [{"text": "Say 'test' and nothing else."}]}]}
        )
        req_headers = {**headers, "Content-Type": "application/json"}

        try:
            resp = await self.session.fetch(
                self.client,
                url,
                method="POST",
                headers=req_headers,
                data=body,
                retry_on_429=False,
            )
            if resp is None:
                return None, None, None

            billing_enabled = None
            quota_remaining = None
            quota_limit = None

            if resp.status_code == 403 and google_error_reason(resp) == "BILLING_DISABLED":
                billing_enabled = False

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

    async def _detect_restrictions(self, key: ValidatedKey) -> KeyRestrictions:
        """
        Detect what restrictions are applied to this Gemini API key.

        For VALID keys: probe with a bogus Referer to confirm no restrictions.
        For BYPASSED keys: infer restriction type from the bypass technique.
        """
        r = KeyRestrictions(restriction_type="unknown")

        if key.status == KeyStatus.VALID:
            # Key works with bare request -- test if a wrong Referer breaks it
            url = f"{GEMINI_BASE_URL}/v1beta/models?key={key.key}"
            try:
                resp = await self.session.fetch(
                    self.client,
                    url,
                    headers={"Referer": "https://evil-test-domain.invalid/"},
                    retry_on_429=False,
                )
                if resp is not None and resp.status_code == 200:
                    # A request from one IP cannot rule out IP or API restrictions.
                    r.restriction_type = "no_referrer_restriction_observed"
                elif resp is not None and google_error_reason(resp) == "API_KEY_HTTP_REFERRER_BLOCKED":
                    r.referrer_restricted = True
                    r.restriction_type = "http_referrer"
            except httpx.HTTPError:
                return r

        elif key.status == KeyStatus.BYPASSED and key.bypass:
            technique = key.bypass.technique.lower()
            bypass_headers = key.bypass.headers

            # Check if bypass used Referer/Origin headers → referrer restriction
            has_referer = any(
                k.lower() in ("referer", "origin") for k in bypass_headers
            )

            if has_referer:
                r.referrer_restricted = True
                r.restriction_type = "http_referrer"
                # Extract the working pattern
                for k, v in bypass_headers.items():
                    if k.lower() == "referer":
                        r.referrer_pattern = v
                        break

                # Confirm: does it fail without the Referer?
                bare_url = f"{GEMINI_BASE_URL}/{key.bypass.api_version}/{key.bypass.endpoint}"
                if not key.bypass.key_in_header:
                    bare_url += f"?key={key.key}"
                non_referer_headers = {
                    k: v for k, v in bypass_headers.items()
                    if k.lower() not in ("referer", "origin")
                }
                try:
                    resp = await self.session.fetch(
                        self.client,
                        bare_url,
                        method=key.bypass.method,
                        headers=non_referer_headers,
                        data=key.bypass.body,
                        retry_on_429=False,
                    )
                    if resp is not None and resp.status_code == 200:
                        # Works without Referer too → not actually referrer-restricted
                        r.referrer_restricted = False
                        r.restriction_type = "unknown"
                except httpx.HTTPError:
                    pass

            elif key.bypass.key_in_header and "api_key_header" in technique:
                # x-goog-api-key header works but ?key= doesn't → application restriction
                r.restriction_type = "application"

            else:
                r.restriction_type = "unknown"

        return r
