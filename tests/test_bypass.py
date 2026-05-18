from geminihunter.validation.bypass import BypassEngine


def test_common_referrer_attempts_include_raw_localhost_and_files_endpoint():
    engine = BypassEngine()

    attempts = engine._common_referrer_attempts(key_in_header=False)

    raw_models = next(
        a for a in attempts if a.technique_name == "common-referer:models:127.0.0.1"
    )
    raw_files = next(
        a for a in attempts if a.technique_name == "common-referer:files:127.0.0.1"
    )

    assert raw_models.headers == {"Referer": "127.0.0.1"}
    assert raw_models.endpoint == "models"
    assert raw_models.key_in_header is False
    assert raw_files.headers == {"Referer": "127.0.0.1"}
    assert raw_files.endpoint == "files"


def test_common_referrer_attempts_can_use_api_key_header_auth():
    engine = BypassEngine()

    attempts = engine._common_referrer_attempts(key_in_header=True)

    assert attempts
    assert all(a.key_in_header for a in attempts)
