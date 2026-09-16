import pytest

from click.testing import CliRunner

from geminihunter import cli


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli.os.path, "expanduser", lambda path: str(tmp_path))


def test_cli_passes_insecure_flag(monkeypatch):
    captured = {}

    class DummyPipeline:
        def __init__(self, config):
            captured["config"] = config

        async def execute(self):
            class Result:
                keys_valid = 0
                keys_bypassed = 0
                keys_rate_limited = 0

            return Result()

    monkeypatch.setattr(cli, "Pipeline", DummyPipeline)

    result = CliRunner().invoke(cli.main, ["example.com", "--insecure"])

    assert captured["config"].insecure is True
    assert result.exit_code == 1


def test_cli_rejects_zero_concurrency():
    result = CliRunner().invoke(cli.main, ["example.com", "--concurrency", "0"])
    assert result.exit_code == 2
    assert "concurrency" in result.output


def test_cli_rejects_directory_input(tmp_path):
    result = CliRunner().invoke(cli.main, ["--file", str(tmp_path)])
    assert result.exit_code == 2


def test_cli_reports_malformed_config(monkeypatch, tmp_path):
    (tmp_path / ".geminihunter.toml").write_text("depth = [")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli.main, ["--key", "synthetic"])
    assert result.exit_code == 2
    assert "configuration" in result.output.lower()


def test_cli_reports_invalid_scan_json(tmp_path):
    scan = tmp_path / "scan.json"
    scan.write_text("[]")
    result = CliRunner().invoke(cli.main, ["--scan-json", str(scan)])
    assert result.exit_code == 2
    assert "JSON" in result.output


@pytest.mark.parametrize("status", [200, 400, 429])
def test_cli_end_to_end_with_mocked_http(mock_http, status):
    import json

    import httpx

    synthetic_key = "AIzaSy" + "0123456789abcdefghijklmnopqrstuvwxyz"[:33]
    mock_http.get("https://example.com/").mock(return_value=httpx.Response(
        200, headers={"Content-Type": "text/html"}, text='<script src="/app.js"></script>',
    ))
    mock_http.get("https://example.com/app.js").mock(return_value=httpx.Response(
        200, headers={"Content-Type": "application/javascript"}, text=f'const key = "{synthetic_key}";',
    ))
    base = "https://generativelanguage.googleapis.com/v1beta"
    payload = {"models": [{"name": "models/mock-model"}]} if status == 200 else {
        "error": {"message": "Synthetic API response"},
    }
    mock_http.get(f"{base}/models").mock(return_value=httpx.Response(status, json=payload))
    if status == 200:
        mock_http.get(f"{base}/tunedModels").mock(return_value=httpx.Response(200, json={}))
        mock_http.get(f"{base}/models/nonexistent-model").mock(return_value=httpx.Response(404, json={}))
        mock_http.post(f"{base}/models/gemini-2.0-flash:generateContent").mock(
            return_value=httpx.Response(200, json={}),
        )
    result = CliRunner().invoke(cli.main, [
        "example.com", "--json", "--no-wayback", "--no-sourcemaps", "--no-bypass",
    ])
    assert result.exit_code == (1 if status == 400 else 0), result.output
    assert result.stdout, repr(result.exception)
    payload = json.loads(result.stdout)
    assert payload["keys_found"] == 1
    assert payload["keys_invalid"] == (1 if status == 400 else 0)
    if status == 200:
        assert payload["results"][0]["available_models"] == ["mock-model"]
        assert payload["results"][0]["billing_enabled"] is None
    assert payload["results"][0]["sources"] == ["https://example.com/app.js"]


def test_cli_config_precedence_and_types(monkeypatch, tmp_path):
    (tmp_path / ".geminihunter.toml").write_text('depth = 4\nconcurrency = 3\nbypass = false\n')
    monkeypatch.chdir(tmp_path)
    captured = {}

    class DummyPipeline:
        def __init__(self, config):
            captured["config"] = config

        async def execute(self):
            from geminihunter.models import ScanResult
            return ScanResult()

    monkeypatch.setattr(cli, "Pipeline", DummyPipeline)
    result = CliRunner().invoke(cli.main, ["example.com", "--depth", "1"])
    assert result.exit_code == 1
    assert captured["config"].depth == 1
    assert captured["config"].concurrency == 3
    assert captured["config"].bypass is False
    for content in ('concurrency = "bad"', 'rate-limit = 0', 'timeout = nan', 'delay = -1', 'unknown = true'):
        (tmp_path / ".geminihunter.toml").write_text(content)
        result = CliRunner().invoke(cli.main, ["example.com"])
        assert result.exit_code == 2, result.output
