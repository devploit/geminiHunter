"""Evidence generation -- curl commands to reproduce findings."""

from geminihunter.models import KeyIntelligence, KeyStatus
from geminihunter.validation.bypass import GEMINI_BASE_URL


def generate_curl_commands(result: KeyIntelligence) -> list[str]:
    """Generate curl commands that reproduce the finding."""
    commands: list[str] = []
    key = result.key

    # Basic validation curl
    base_url = f"{GEMINI_BASE_URL}/v1beta/models?key={key}"
    commands.append(f'curl -s "{base_url}"')

    # If bypassed, include the bypass curl
    if result.bypass:
        bypass = result.bypass
        url = f"{GEMINI_BASE_URL}/{bypass.api_version}/{bypass.endpoint}?key={key}"

        parts = [f"curl -s -X {bypass.method}"]
        for k, v in bypass.headers.items():
            parts.append(f'-H "{k}: {v}"')
        parts.append(f'"{url}"')
        commands.append(" ".join(parts))

    # Generate content curl (proves the key can do real work)
    if result.status in (KeyStatus.VALID, KeyStatus.BYPASSED):
        gen_url = f"{GEMINI_BASE_URL}/v1beta/models/gemini-2.0-flash:generateContent?key={key}"
        headers = '-H "Content-Type: application/json"'
        if result.bypass:
            for k, v in result.bypass.headers.items():
                headers += f' -H "{k}: {v}"'
        body = """'{"contents":[{"parts":[{"text":"Say test"}]}]}'"""
        commands.append(f'curl -s -X POST {headers} -d {body} "{gen_url}"')

    return commands
