import shlex

from geminihunter.output.evidence import _build_curl
from geminihunter.validation.bypass import BypassAttempt


def test_curl_preserves_untrusted_values_as_single_shell_arguments():
    url = "https://example.com/a'b?x=$(id)"
    header = "https://example.com/' ; echo injected ; '"
    body = '{"text":"it\'s a test $(id)"}'
    command = _build_curl("POST", url, {"Referer": header}, body)
    tokens = shlex.split(command.replace("\\\n", ""))
    assert tokens == ["curl", "-s", "-X", "POST", "-H", f"Referer: {header}", "-d", body, url]


def test_bypass_curl_quotes_shell_expansions():
    attempt = BypassAttempt(technique_name="test", headers={"Referer": "$(id)`id`"})
    command = attempt.to_curl("synthetic-key")
    assert "'Referer: $(id)`id`'" in command
    assert shlex.split(command)[-1] == attempt.to_url("synthetic-key")
