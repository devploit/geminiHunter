"""Key validation orchestrator."""

import asyncio
import logging

import httpx
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from geminihunter.config import Config
from geminihunter.models import ExtractedKey, KeyStatus, ValidatedKey
from geminihunter.validation.bypass import GEMINI_BASE_URL, BypassEngine

logger = logging.getLogger("geminihunter")
console = Console(stderr=True)


class KeyValidator:
    """Validates API keys against the Google Gemini API."""

    def __init__(self, client: httpx.AsyncClient, config: Config):
        self.client = client
        self.config = config
        self.bypass_engine = BypassEngine()

    async def validate_all(self, keys: list[ExtractedKey]) -> list[ValidatedKey]:
        """Validate all extracted keys with concurrency control."""
        sem = asyncio.Semaphore(self.config.concurrency)

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            disable=self.config.quiet,
        )

        with progress:
            task_id = progress.add_task("Validating keys...", total=len(keys))

            async def validate_with_progress(key: ExtractedKey) -> ValidatedKey:
                result = await self._validate_one(key, sem)
                progress.advance(task_id)
                return result

            tasks = [validate_with_progress(k) for k in keys]
            results = await asyncio.gather(*tasks)

        # Summary
        valid = sum(1 for r in results if r.status == KeyStatus.VALID)
        bypassed = sum(1 for r in results if r.status == KeyStatus.BYPASSED)
        forbidden = sum(1 for r in results if r.status == KeyStatus.FORBIDDEN)
        invalid = sum(1 for r in results if r.status == KeyStatus.INVALID)

        if not self.config.quiet:
            console.print(
                f"  [green]{valid} valid[/green] | "
                f"[yellow]{bypassed} bypassed[/yellow] | "
                f"[red]{forbidden} forbidden[/red] | "
                f"[dim]{invalid} invalid[/dim]"
            )

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
                logger.info(f"Key ...{key.key[-8:]} is VALID")
                return ValidatedKey(
                    key=key.key,
                    status=KeyStatus.VALID,
                    initial_status_code=status_code,
                    target_domain=key.target_domain,
                    sources=key.sources,
                    raw_response=resp.text,
                )

            if status_code == 403 and self.config.bypass:
                logger.info(
                    f"Key ...{key.key[-8:]} returned 403, running bypass engine..."
                )
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

            # 400, 401, or other = invalid
            return ValidatedKey(
                key=key.key,
                status=KeyStatus.INVALID,
                initial_status_code=status_code,
                target_domain=key.target_domain,
                sources=key.sources,
            )
