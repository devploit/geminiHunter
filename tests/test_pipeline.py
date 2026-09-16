import json

import pytest

from geminihunter.config import Config
from geminihunter.models import ExtractedKey, KeyIntelligence, KeyStatus, SourceType, ValidatedKey
from geminihunter.pipeline import Pipeline


@pytest.mark.asyncio
async def test_empty_scan_writes_json(monkeypatch, capsys):
    pipeline = Pipeline(Config(targets=["example.com"], json_mode=True))

    async def discover():
        return [], 0

    monkeypatch.setattr(pipeline, "_discover", discover)
    result = await pipeline.execute()
    assert json.loads(capsys.readouterr().out)["results"] == []
    assert result.keys_found == 0


@pytest.mark.asyncio
async def test_json_file_output_and_mixed_input_deduplication(monkeypatch, tmp_path):
    output = tmp_path / "results.json"
    pipeline = Pipeline(Config(
        targets=["example.com"], keys=["synthetic-key"], output_path=str(output), quiet=True,
    ))

    async def discover():
        return [], 1

    async def validate(keys):
        assert len(keys) == 1
        assert keys[0].sources == ["https://example.com/app.js", "direct_input"]
        return [ValidatedKey(key=keys[0].key, status=KeyStatus.INVALID)]

    monkeypatch.setattr(pipeline, "_discover", discover)
    monkeypatch.setattr(pipeline, "_extract", lambda sources: [ExtractedKey(
        key="synthetic-key", sources=["https://example.com/app.js"],
        source_types=[SourceType.JS_FILE], target_domain="example.com",
        target_domains=["example.com"],
    )])
    monkeypatch.setattr(pipeline, "_validate", validate)
    result = await pipeline.execute()
    assert json.loads(output.read_text())["keys_found"] == 1
    assert result.keys_found == 1


@pytest.mark.asyncio
async def test_empty_apk_scan_reports_apk_target(monkeypatch, tmp_path):
    output = tmp_path / "results.json"
    pipeline = Pipeline(Config(apk_paths=["sample.apk"], output_path=str(output), quiet=True))

    async def discover():
        return [], 0

    monkeypatch.setattr(pipeline, "_discover", discover)
    await pipeline.execute()
    assert json.loads(output.read_text())["targets_scanned"] == ["sample.apk"]


def test_text_file_output_does_not_leak_to_stdout(tmp_path, capsys):
    from geminihunter.models import ScanResult

    output = tmp_path / "results.txt"
    pipeline = Pipeline(Config(output_path=str(output), quiet=True))
    pipeline._render(ScanResult(results=[KeyIntelligence(key="synthetic-key", status=KeyStatus.INVALID)]))
    assert "INVALID" in output.read_text()
    assert capsys.readouterr().out == ""
