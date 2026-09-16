<p align="center">
  <img src="assets/logo.png" alt="geminiHunter" width="200">
</p>

<h1 align="center">geminiHunter</h1>

<p align="center">
  Find and assess exposed Google Gemini API keys in web assets and Android apps.
</p>

<p align="center">
  <a href="https://github.com/devploit/geminiHunter/actions/workflows/ci.yml"><img src="https://github.com/devploit/geminiHunter/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python 3.11 or later"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License"></a>
</p>

## Overview

geminiHunter discovers candidate keys in JavaScript, source maps, archived assets, and APK/XAPK files. It deduplicates findings, validates access to the Gemini API, and reports source locations and observed restrictions. For forbidden keys, an optional bounded bypass engine tests request variations and records the outcome.

- **Web discovery:** HTML scripts, linked JavaScript, JSON manifests, framework assets, source maps, webpack chunks, and Wayback snapshots.
- **Android discovery:** jadx decompilation when available, with ZIP and binary-string scanning as a fallback.
- **Extraction:** plain keys, concatenated strings, arrays, template literals, reversed strings, hex escapes, and Base64.
- **Reporting:** readable terminal output, JSON, and shell-quoted curl evidence.

Use only within an authorized testing scope. This is an active scanner: API validation, bypass probes, and intelligence gathering contact Google, and some probes can generate content and consume quota. Reports and evidence can contain complete credentials. See [SECURITY.md](SECURITY.md).

## Installation

Requires **Python 3.11+**. Install directly from GitHub with [pipx](https://pipx.pypa.io/):

```bash
pipx install git+https://github.com/devploit/geminiHunter.git
geminihunter --version
```

Update with `pipx upgrade geminihunter`. Alternatively, install into a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install git+https://github.com/devploit/geminiHunter.git
```

On Windows, activate with `.venv\Scripts\Activate.ps1` in PowerShell. The module entry point is also available as `python -m geminihunter`.

For full APK decompilation, install [jadx](https://github.com/skylot/jadx) and make it available on `PATH`. On macOS: `brew install jadx`. Without it, ZIP and binary-string extraction still work.

## Quick start

Replace `example.com` and the local filenames below with inputs you are authorized to test.

```bash
# Discover keys in a web target
geminihunter example.com

# Check previously collected keys without exposing them in command arguments
geminihunter --key-file keys.txt

# Scan an Android app
geminihunter --apk app.apk

# Save a structured report, including an empty report if no keys are found
geminihunter example.com -o results.json
```

## Usage

### Input

```bash
# Multiple domains or full HTTP(S) URLs
geminihunter app.example.com https://example.com/app/

# One target per line; blank lines and # comments are ignored
geminihunter -f targets.txt

# Read targets from a pipe
cat targets.txt | geminihunter --json

# Import a gengar-style JSON scan
geminihunter --scan-json scan.json

# Read keys from stdin instead of targets
cat keys.txt | geminihunter -k -

# XAPK bundles and split APKs
geminihunter --apk app.xapk
geminihunter --apk base.apk --apk split_config.apk

# Combine discovery with existing keys
geminihunter --apk app.apk -f targets.txt --key-file keys.txt
```

Scan JSON accepts `services` objects with string `url` and `host` fields, `subdomains` objects with a string `domain`, or `scan.targets` as an array of strings. Services take precedence; HTTPS is preferred for duplicate hosts.

Direct keys can also be supplied with `-k KEY` or `-k KEY1,KEY2`; these values can appear in shell history and process listings. Neither direct key input nor APK input suppresses target stdin: reserve stdin for keys explicitly with `-k -`.

### Discovery and network controls

```bash
geminihunter example.com --depth 3 --no-wayback
geminihunter example.com --no-sourcemaps --no-bypass
geminihunter -f targets.txt --concurrency 5 --rate-limit 2 --delay 0.5
geminihunter example.com --timeout 20 --proxy http://127.0.0.1:8080
geminihunter example.com --proxy proxies.txt --user-agent "MyAuthorizedScanner/1.0"
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--depth` | `2` | Maximum page-link depth; `0` includes the initial page and its assets |
| `--wayback / --no-wayback` | Enabled | Fetch archived JavaScript through Wayback |
| `--sourcemaps / --no-sourcemaps` | Enabled | Follow source maps |
| `--bypass / --no-bypass` | Enabled | Try request variations after a 403 response |
| `--rate-limit` | `10` | Token refill rate per second; permits an initial burst |
| `--delay` | `0` | Delay before each request, in seconds |
| `--timeout` | `15` | HTTP timeout; discovery phases use shorter caps |
| `--concurrency` | `20` | Concurrency setting for pipeline stages and connection pools |
| `--user-agent` | `rotate` | Rotating user agent, or a fixed custom value |
| `--insecure` | Disabled | Disable TLS certificate verification |

The concurrency setting is not a strict global in-flight request limit: some stages perform nested probes. Proxies rotate when a session client is created. Retry attempts also consume rate-limit tokens; Retry-After waits are capped at 60 seconds.

Discovery can fetch linked assets on external hosts. Wayback queries expand targets to an inferred parent domain, so review that scope before enabling them. Parent-domain inference is heuristic, not a full public-suffix lookup.

### Output

```bash
# JSON on stdout; diagnostic output stays on stderr
geminihunter example.com --json

# File extension selects JSON; other extensions receive a text report
geminihunter example.com -o results.json
geminihunter example.com -o results.txt

# Include curl evidence in terminal output
geminihunter example.com --evidence

# Suppress banner and progress
geminihunter example.com -q --json
```

`--json` always selects JSON, regardless of the output filename. With `-o`, the report goes to the file; without it, JSON goes to stdout and terminal reports go to stderr. JSON includes curl evidence automatically. Existing output files are overwritten.

For the complete option list, run `geminihunter --help`. Add `-v` for diagnostic logs; treat those logs as sensitive.

## Understanding results

| Status | Meaning |
| --- | --- |
| `valid` | The initial model-list request returned 200 |
| `bypassed` | A forbidden key subsequently returned 200 with a recorded request variation |
| `rate_limited` | A 429 response was observed; a working generation call is not confirmed |
| `forbidden` | Access remains forbidden, including cases where the error reason changed |
| `invalid` | Validation returned 400 or 401 |
| `unknown` | Transport failure or an unexpected endpoint response prevented validation |

A 429 candidate from the bypass engine is rechecked before being labeled `bypassed`. Permission progress from a referrer restriction to `SERVICE_DISABLED` remains `forbidden`. See [bypass behavior and extension points](docs/bypass.md).

For valid and bypassed keys, the tool probes model listings, tuned-model listings, project identifiers, quota headers, and restrictions. These are observations, not a complete cloud-account audit:

- A successful generation request does not establish paid billing: Gemini also offers a [free tier](https://ai.google.dev/gemini-api/docs/billing). `billing_enabled` remains `null` unless a billing-disabled response is explicitly identified.
- A successful request with an arbitrary referrer cannot rule out IP or API restrictions. The tool records `no_referrer_restriction_observed` instead of declaring the key unrestricted. See [Google's restriction types](https://docs.cloud.google.com/api-keys/docs/add-restrictions-api-keys).
- Model lists reflect the returned API page; pagination is not currently followed. Tuned-model and quota information may be unavailable. A tuned-model listing does not establish access to training data.
- Some existing probes use fixed model names and API versions, which may become unavailable. A failed probe is not proof that all model access is blocked.

### JSON and exit codes

Top-level JSON fields include `targets_scanned`, `sources_crawled`, `keys_found`, per-status counts, `duration_seconds`, `phase_timings`, and `results`. Each result includes `key`, `status`, `sources`, `target_domain`, optional `bypass` details, intelligence fields, and `curl_commands`.

```bash
# Print statuses and source locations without printing the keys
geminihunter -f targets.txt -q --json | jq '.results[] | {status, sources}'

# Inspect permission progress
geminihunter --key-file keys.txt --json | jq '.results[] | select(.bypass) | {status, bypass: .bypass.technique, code: .bypass.bypass_status_code}'
```

| Exit code | Meaning |
| --- | --- |
| `0` | At least one valid, bypassed, or rate-limited key |
| `1` | No such findings, or an operational error reported on stderr |
| `2` | Invalid arguments, input structure, or configuration |
| `130` | Interrupted by the user |

A valid JSON report is emitted even when discovery finds no keys. Use the status fields to distinguish confirmed access from rate limiting; exit code 0 alone does not establish unrestricted access.

## Configuration

Create `.geminihunterrc` or `.geminihunter.toml` in the working directory or home directory:

```toml
depth = 2
wayback = true
sourcemaps = true
bypass = true
rate-limit = 5.0
delay = 0.2
timeout = 20.0
concurrency = 10
user-agent = "rotate"
insecure = false
evidence = false
```

The first file found is used: working directory before home, and `.geminihunterrc` before `.geminihunter.toml`. Files are not merged. Explicit CLI options override file values. Malformed TOML, unsupported settings, and invalid option values produce an error.

## APK limits

Archive inputs are validated before decompilation or extraction. Unsafe paths and symbolic-link entries are rejected. Each archive is limited to 10,000 entries and 512 MiB of declared uncompressed data; an APK inside an XAPK is limited to 256 MiB. Individual source files above 10 MiB are skipped. XAPK processing extracts nested APKs and reads supported metadata, without unpacking unrelated assets.

jadx runs with a 180-second timeout; unavailable or unsuccessful decompilation falls back to ZIP scanning. These limits are guardrails, not a sandbox for a third-party decompiler.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, tests, and package verification. [CHANGELOG.md](CHANGELOG.md) tracks changes.

```text
src/geminihunter/
  cli.py              Input, configuration, and exit codes
  pipeline.py         Discovery → extraction → validation → reporting
  discovery/          Web, archive, source-map, and APK discovery
  extraction/         Key patterns and deobfuscation
  validation/         API validation and bypass orchestration
  intelligence/       Post-validation probes
  network/            Sessions, retries, rate limiting, transport errors
  output/             Terminal, JSON, and curl evidence
```

## License

Licensed under the [MIT License](LICENSE).

## Author

[@devploit](https://github.com/devploit)
