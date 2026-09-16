import base64

import pytest

from geminihunter.extraction.extractor import KeyExtractor
from geminihunter.models import DiscoveredSource, SourceType


KEY = "AIzaSy" + "0123456789abcdefghijklmnopqrstuvwxyz"[:33]
SUFFIX = KEY[6:]


@pytest.mark.parametrize("content", [
    f'const key = "{KEY}";',
    f'const key = "AIzaSy" + "{SUFFIX}";',
    f'const key = "AIzaSy" + "{SUFFIX[:10]}" + "{SUFFIX[10:]}";',
    f'const key = ["AIzaSy", "{SUFFIX}"].join("");',
    'const key = `AIzaSy${"' + SUFFIX + '"}`;',
    f'const key = "{KEY[::-1]}";',
    f'const key = fallback || "{KEY}";',
    r'const key = "\x41\x49\x7a\x61\x53\x79' + SUFFIX + '";',
    f'const key = "{base64.b64encode(KEY.encode()).decode()}";',
])
def test_supported_key_representations(content):
    extractor = KeyExtractor()
    assert extractor.may_contain_key_material(content)
    source = DiscoveredSource(
        url="https://example.com/app.js", source_type=SourceType.JS_FILE,
        target_domain="example.com", content=content,
    )
    assert extractor.extract_from_source(source) == [KEY]


def test_extraction_merges_provenance_and_ignores_placeholders():
    extractor = KeyExtractor()
    for domain in ("a.example.com", "b.example.com"):
        extractor.extract_from_source(DiscoveredSource(
            url=f"https://{domain}/app.js", source_type=SourceType.JS_FILE,
            target_domain=domain, content=f'"{KEY}" "AIzaSy{"x" * 33}"',
        ))
    assert extractor.count == 1
    assert extractor.all_keys[0].target_domains == ["a.example.com", "b.example.com"]
    assert len(extractor.all_keys[0].sources) == 2
