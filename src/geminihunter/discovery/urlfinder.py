"""Helpers to extract crawl-worthy asset URLs from HTML and JSON-like payloads."""

import json
import re
from urllib.parse import urljoin

# HTML asset references
SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]+src\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
JS_URL_RE = re.compile(
    r"""["']((?:https?://[^"']+|/[^"']+)\.(?:js|mjs|json|webmanifest)(?:\?[^"']*)?)["']""",
    re.IGNORECASE,
)
PRELOAD_SCRIPT_RE = re.compile(
    r'<link[^>]+rel\s*=\s*["\'](?:preload|modulepreload)["\'][^>]+href\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
PRELOAD_SCRIPT_RE2 = re.compile(
    r'<link[^>]+href\s*=\s*["\']([^"\']+)["\'][^>]+rel\s*=\s*["\'](?:preload|modulepreload)["\']',
    re.IGNORECASE,
)
MANIFEST_RE = re.compile(
    r'<link[^>]+rel\s*=\s*["\']manifest["\'][^>]+href\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
SERVICE_WORKER_RE = re.compile(
    r"""navigator\.serviceWorker\.register\(\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
WORKBOX_RE = re.compile(
    r"""["'](/(?:sw|service-worker|workbox)(?:[-\w./]*)\.(?:js|mjs))["']""",
    re.IGNORECASE,
)
NEXTJS_DATA_RE = re.compile(
    r"""["'](/_next/(?:data/[^"'/]+/[^"']+\.json|static/[^"']+\.js))["\']""",
    re.IGNORECASE,
)
NUXT_CHUNK_RE = re.compile(
    r"""["'](/_nuxt/[^"']+\.(?:js|mjs|json))["\']""",
    re.IGNORECASE,
)
FIREBASE_INIT_RE = re.compile(
    r"""["'](/__/firebase/[^"']+\.(?:json|js))["\']""",
    re.IGNORECASE,
)
ASTRO_RE = re.compile(
    r"""["'](/_astro/[^"']+\.(?:js|mjs|json))["\']""",
    re.IGNORECASE,
)
SVELTEKIT_RE = re.compile(
    r"""["'](/_app/immutable/[^"']+\.(?:js|mjs|json))["\']""",
    re.IGNORECASE,
)
REMIX_RE = re.compile(
    r"""["'](/build/[^"']+\.(?:js|mjs|json))["\']""",
    re.IGNORECASE,
)
ANGULAR_RE = re.compile(
    r"""["']((?:/)?(?:runtime|polyfills|main|scripts|styles)(?:\.[a-f0-9]+)?\.(?:js|mjs))["\']""",
    re.IGNORECASE,
)
IMPORTMAP_SCRIPT_RE = re.compile(
    r'<script[^>]+type\s*=\s*["\']importmap["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)
NEXT_DATA_SCRIPT_RE = re.compile(
    r'<script[^>]+id\s*=\s*["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)
VITE_MANIFEST_ENTRY_RE = re.compile(
    r'''"(?:file|src|imports|dynamicImports)"\s*:\s*(\[[^\]]+\]|"[^"]+")''',
    re.IGNORECASE,
)
URLISH_RE = re.compile(
    r"""(?:(?:https?:)?//[^\s"'<>]+|/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+\.(?:js|mjs|json|webmanifest))(?:\?[^\s"'<>]*)?""",
    re.IGNORECASE,
)


def normalize_url(base: str, href: str) -> str:
    """Resolve a potentially relative URL against a base."""
    if href.startswith(("http://", "https://", "//")):
        if href.startswith("//"):
            return f"https:{href}"
        return href
    return urljoin(base, href)


def _json_value_urls(base_url: str, value) -> list[str]:
    urls: list[str] = []
    if isinstance(value, str):
        if value.endswith((".js", ".mjs", ".json", ".webmanifest")) or value.startswith(("/", "http://", "https://", "//")):
            urls.append(normalize_url(base_url, value))
    elif isinstance(value, list):
        for item in value:
            urls.extend(_json_value_urls(base_url, item))
    elif isinstance(value, dict):
        for item in value.values():
            urls.extend(_json_value_urls(base_url, item))
    return urls


def _dedupe(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for url in urls:
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def extract_asset_urls_from_html(base_url: str, text: str) -> list[str]:
    """Extract JS/JSON/manifest assets from HTML-ish content."""
    urls: list[str] = []

    for regex in (
        SCRIPT_SRC_RE,
        JS_URL_RE,
        PRELOAD_SCRIPT_RE,
        PRELOAD_SCRIPT_RE2,
        MANIFEST_RE,
        SERVICE_WORKER_RE,
        WORKBOX_RE,
        NEXTJS_DATA_RE,
        NUXT_CHUNK_RE,
        FIREBASE_INIT_RE,
        ASTRO_RE,
        SVELTEKIT_RE,
        REMIX_RE,
        ANGULAR_RE,
    ):
        for match in regex.finditer(text):
            urls.append(normalize_url(base_url, match.group(1)))

    for match in IMPORTMAP_SCRIPT_RE.finditer(text):
        try:
            data = json.loads(match.group(1))
        except (ValueError, json.JSONDecodeError):
            continue
        for mapped_url in data.get("imports", {}).values():
            if isinstance(mapped_url, str):
                urls.append(normalize_url(base_url, mapped_url))

    for match in NEXT_DATA_SCRIPT_RE.finditer(text):
        try:
            data = json.loads(match.group(1))
        except (ValueError, json.JSONDecodeError):
            continue
        build_id = data.get("buildId")
        if build_id:
            urls.append(normalize_url(base_url, f"/_next/static/{build_id}/_buildManifest.js"))
            urls.append(normalize_url(base_url, f"/_next/static/{build_id}/_ssgManifest.js"))
        page_props = data.get("props", {})
        urls.extend(_json_value_urls(base_url, page_props))

    return _dedupe(urls)


def extract_asset_urls_from_json(base_url: str, text: str) -> list[str]:
    """Extract asset URLs from JSON, manifests and JSON-like payloads."""
    urls: list[str] = []
    try:
        data = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        data = None

    if data is not None:
        urls.extend(_json_value_urls(base_url, data))
    else:
        for match in VITE_MANIFEST_ENTRY_RE.finditer(text):
            raw = match.group(1)
            try:
                parsed = json.loads(raw)
            except (ValueError, json.JSONDecodeError):
                parsed = raw.strip('"')
            urls.extend(_json_value_urls(base_url, parsed))

        for candidate in URLISH_RE.findall(text):
            if candidate.endswith((".js", ".mjs", ".json", ".webmanifest")):
                urls.append(normalize_url(base_url, candidate))

    return _dedupe(urls)
