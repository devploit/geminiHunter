"""Evidence generation -- curl commands to reproduce findings."""

from geminihunter.models import KeyIntelligence, KeyStatus
from geminihunter.validation.bypass import GEMINI_BASE_URL


def _build_curl(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
) -> str:
    """Build a multi-line curl command with \\ continuations."""
    parts = ["curl -s"]
    if method != "GET":
        parts.append(f"-X {method}")
    for k, v in (headers or {}).items():
        parts.append(f"-H '{k}: {v}'")
    if body:
        parts.append(f"-d '{body}'")
    parts.append(f"'{url}'")
    return " \\\n  ".join(parts)


def generate_curl_commands(result: KeyIntelligence) -> list[str]:
    """Generate curl commands that reproduce the finding."""
    commands: list[str] = []
    key = result.key

    # 1. Show the 403: basic request without bypass
    commands.append(
        _build_curl("GET", f"{GEMINI_BASE_URL}/v1beta/models?key={key}")
    )

    # 2. Bypass PoC (exact technique that works, with body)
    if result.bypass:
        bp = result.bypass
        url = f"{GEMINI_BASE_URL}/{bp.api_version}/{bp.endpoint}?key={key}"
        commands.append(_build_curl(bp.method, url, bp.headers, bp.body))

    # 3. Generate content curl (proves the key can do real work)
    # Skip if bypass already uses generateContent
    if result.status in (KeyStatus.VALID, KeyStatus.BYPASSED):
        skip = result.bypass and "generateContent" in result.bypass.endpoint
        if not skip:
            gen_url = f"{GEMINI_BASE_URL}/v1beta/models/gemini-2.0-flash:generateContent?key={key}"
            hdrs = {"Content-Type": "application/json"}
            if result.bypass:
                hdrs.update(result.bypass.headers)
            body = '{"contents":[{"parts":[{"text":"Say test"}]}]}'
            commands.append(_build_curl("POST", gen_url, hdrs, body))

    return commands
