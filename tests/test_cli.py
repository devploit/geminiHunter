from click.testing import CliRunner

from geminihunter import cli


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
