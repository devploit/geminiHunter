from geminihunter.config import Config
from geminihunter.discovery.crawler import Crawler, MAX_ASSETS_PER_PAGE


def test_crawler_prioritizes_same_domain_assets():
    crawler = Crawler(client=object(), config=Config(), session=object())
    urls = [
        *(f"https://example.com/assets/{i}.js" for i in range(80)),
        *(f"https://cdn.example.net/{i}.js" for i in range(30)),
        *(f"https://example.com/_next/data/{i}.json" for i in range(20)),
    ]

    selected = crawler._prioritize_asset_urls(list(urls), "example.com")

    assert len(selected) <= MAX_ASSETS_PER_PAGE
    assert selected[0].startswith("https://example.com/assets/")
