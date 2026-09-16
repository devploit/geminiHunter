import io

from rich.console import Console

from geminihunter.config import Config
from geminihunter.models import KeyIntelligence, KeyStatus, ScanResult
from geminihunter.output.console import render_table


def test_terminal_treats_source_and_api_data_as_literal_text():
    source = "https://example.com/[/unexpected].js"
    result = ScanResult(results=[KeyIntelligence(
        key="synthetic-key", status=KeyStatus.VALID, sources=[source],
        target_domain="[/unexpected]", available_models=["[/unexpected]"],
        detail="[/unexpected]", curl_commands=["curl 'https://example.com/[x]'"],
    )])
    console = Console(file=io.StringIO(), record=True, width=120)
    output = render_table(result, Config(evidence=True), console)
    assert source in output
    assert "curl 'https://example.com/[x]'" in output
