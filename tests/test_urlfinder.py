from geminihunter.discovery.urlfinder import (
    extract_asset_urls_from_html,
    extract_asset_urls_from_json,
)


def test_extract_asset_urls_from_html_modern_spa():
    html = """
    <link rel="modulepreload" href="/assets/app-123.mjs">
    <script type="importmap">{"imports":{"app":"/assets/main.js"}}</script>
    <script id="__NEXT_DATA__">{"buildId":"BUILD123","props":{"pageProps":{"chunk":"/_next/data/BUILD123/index.json"}}}</script>
    <script>navigator.serviceWorker.register('/sw.js')</script>
    """
    urls = extract_asset_urls_from_html("https://example.com/", html)

    assert "https://example.com/assets/app-123.mjs" in urls
    assert "https://example.com/assets/main.js" in urls
    assert "https://example.com/_next/static/BUILD123/_buildManifest.js" in urls
    assert "https://example.com/sw.js" in urls


def test_extract_asset_urls_from_json_manifest_like_payload():
    payload = """
    {
      "main.js": {"file": "assets/main-abc.js", "imports": ["assets/vendor-def.js"]},
      "worker": "/workbox-123.js"
    }
    """
    urls = extract_asset_urls_from_json("https://example.com/manifest.json", payload)

    assert "https://example.com/assets/main-abc.js" in urls
    assert "https://example.com/assets/vendor-def.js" in urls
    assert "https://example.com/workbox-123.js" in urls
