# Changelog

## Unreleased

- Add GitHub CI for tests, lint, distribution builds, dependency audits, and secret scanning.
- Add an MIT license, package metadata, contribution guidance, security reporting guidance, and a single version source.
- Emit JSON for empty scans and `.json` output files; preserve APK target labels and deduplicate mixed key input.
- Validate numeric options, TOML configuration, input file types, and scan JSON with actionable errors.
- Apply rate limits to retries, support bounded HTTP-date Retry-After headers, preserve final HTTP responses, and avoid mutating caller headers.
- Correct reversed-key extraction and render remote content as literal terminal text.
- Quote shell arguments in evidence commands and validate archive paths and expansion limits.
- Avoid reporting paid billing, unrestricted keys, or invalid credentials without sufficient evidence.
- Require a patched HTTP/2 dependency and expand regression tests with mocked network access.
