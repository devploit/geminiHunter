<p align="center">
  <pre>
                    _       _ __  __            __
   ____ ____  ____ (_)___  (_) / / /_  ______  / /____  _____
  / __ `/ _ \/ __ `__ \/ / __ \/ / /_/ / / / / __ \/ __/ _ \/ ___/
 / /_/ /  __/ / / / / / / / / / / __  / /_/ / / / / /_/  __/ /
 \__, /\___/_/ /_/ /_/_/_/ /_/_/_/ /_/\__,_/_/ /_/\__/\___/_/
/____/
  </pre>
</p>

<p align="center">
  <b>Bug bounty tool to discover, validate, and bypass Google Gemini API keys</b>
</p>

<p align="center">
  <a href="https://github.com/devploit/geminiHunter/releases"><img src="https://img.shields.io/github/v/release/devploit/geminiHunter?style=flat-square" alt="Release"></a>
  <a href="https://github.com/devploit/geminiHunter/blob/main/LICENSE"><img src="https://img.shields.io/github/license/devploit/geminiHunter?style=flat-square" alt="License"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" alt="Python"></a>
</p>

---

## Features

- **Discovery** -- Crawls domains/subdomains extracting API keys from HTML, JS files, source maps (`.js.map`), webpack chunks, and Wayback Machine historical JS
- **JS Deobfuscation** -- Beautifies minified JS before regex extraction to catch split/concatenated keys
- **Validation** -- Tests extracted keys against the Google Gemini API
- **403 Bypass Engine** -- 9 bypass strategies with auto-registry pattern:
  - Referer rotation (Google, target domain, common values)
  - Origin header manipulation
  - X-Forwarded-For / X-Real-IP spoofing
  - API version bruteforce (v1, v1beta, v1beta2, v1beta3)
  - Endpoint switching (models, generateContent, embedContent, countTokens)
  - HTTP method switching
  - Combo strategies (Referer + version, Referer + endpoint)
- **Key Intelligence** -- Enumerates available models, billing status, quota, and GCP project ID
- **OPSEC** -- Proxy rotation, rate limiting, User-Agent rotation, configurable delays
- **Flexible Input** -- Domains, files, stdin pipe, scan JSON (gengar-style), or direct API keys
- **Pipeline-friendly** -- JSON output, exit codes, stdin/stdout compatible with recon tools

## Installation

```bash
git clone https://github.com/devploit/geminiHunter.git
cd geminiHunter
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

### Discovery mode -- scan targets for keys

```bash
# Single domain
geminihunter example.com

# File with targets
geminihunter -f subdomains.txt

# Scan JSON (gengar-style)
geminihunter -sj scan-results.json

# Pipe from recon tools
subfinder -d example.com | httpx -silent | geminihunter

# JSON output to file
geminihunter -f subs.txt --json -o results.json
```

### Key-check mode -- validate keys directly

```bash
# Single key
geminihunter -k AIzaSyYOUR_KEY_HERE

# Multiple keys
geminihunter -k key1,key2,key3

# From file
geminihunter --key-file found_keys.txt

# From stdin
echo "AIzaSy..." | geminihunter -k -
```

### Options

```
Usage: geminihunter [OPTIONS] [TARGETS]...

Options:
  -f, --file PATH                 File with targets (one per line)
  -sj, --scan-json PATH          Scan JSON file (gengar-style: extracts subdomains)
  -k, --key TEXT                  API key(s) to check directly (comma-separated, or - for stdin)
  --key-file PATH                 File with API keys (one per line)
  --depth INTEGER                 Crawl depth  [default: 2]
  --wayback / --no-wayback        Include Wayback Machine JS  [default: wayback]
  --sourcemaps / --no-sourcemaps  Chase .js.map files  [default: sourcemaps]
  --bypass / --no-bypass          Run 403 bypass engine  [default: bypass]
  --proxy TEXT                    Proxy URL or file with proxy list
  --rate-limit FLOAT              Max requests/second  [default: 10.0]
  --delay FLOAT                   Fixed delay between requests (seconds)  [default: 0.0]
  --timeout FLOAT                 HTTP timeout (seconds)  [default: 15.0]
  --concurrency INTEGER           Max concurrent requests  [default: 20]
  --user-agent TEXT               Custom User-Agent or "rotate"  [default: rotate]
  -o, --output PATH               Write results to file
  --json                          Output as JSON
  -v, --verbose                   Verbose logging
  -q, --quiet                     Suppress banner and progress
  --evidence                      Include curl reproduction commands
  --version                       Show the version and exit
  --help                          Show this message and exit
```

## Architecture

```
Mode 1 (Discovery):                  Mode 2 (Direct -k):
  Targets (stdin/file/args/json)       Keys (--key / --key-file / stdin)
      |                                    |
  Discovery (crawl, wayback,               |
             sourcemaps, webpack)          |
      |                                    |
  Extraction (deobfuscate, regex,          |
              dedup)                       |
      \_______________  __________________/
                      \/
                 Validation  -- test against Gemini API
                      |
                 Bypass Engine  -- 403 bypass strategies
                      |
                 Intelligence  -- models, billing, quota, project ID
                      |
                 Output  -- rich table / JSON + curl evidence
```

## Integration with recon pipelines

geminiHunter is designed to fit into existing bug bounty workflows:

```bash
# subfinder -> httpx -> geminiHunter
subfinder -d target.com -silent | httpx -silent | geminihunter --json | jq '.results[] | select(.status == "valid" or .status == "bypassed")'

# With proxy rotation
geminihunter -f targets.txt --proxy proxies.txt --rate-limit 5

# Quiet mode for scripting
geminihunter -f subs.txt -q --json | jq -r '.results[].key'
```

**Exit codes**: `0` if valid/bypassed keys found, `1` otherwise.

## Bypass techniques

| # | Technique | Description |
|---|-----------|-------------|
| 1 | `referer_google` | Referer: google.com, aistudio, cloud console |
| 2 | `referer_target` | Referer: target domain variants |
| 3 | `referer_common` | Referer: googleapis.com, localhost, empty |
| 4 | `origin_header` | Origin header manipulation |
| 5 | `xff_bypass` | X-Forwarded-For / X-Real-IP with internal IPs |
| 6 | `api_version` | API version bruteforce (v1, v1beta, v1beta2, v1beta3) |
| 7 | `endpoint_switch` | Different endpoints (models, generateContent, embedContent, countTokens) |
| 8 | `method_switch` | HTTP method switching (POST, OPTIONS, HEAD) |
| 9 | `combo_*` | Combinations of Referer + version/endpoint |

## Adding custom bypass strategies

The bypass engine uses an auto-registry pattern. To add a new strategy, create a class in `src/geminihunter/validation/bypass.py`:

```python
@bypass_strategy
class MyCustomBypass(BypassStrategy):
    name = "my_custom_bypass"

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        return [
            BypassAttempt(
                technique_name="my_custom_bypass",
                headers={"X-Custom": "value"},
            )
        ]
```

That's it. No other file needs modification.

## Disclaimer

This tool is intended for **authorized security testing and bug bounty programs only**. Always ensure you have explicit permission before testing any target. The author is not responsible for any misuse.

## Author

[@devploit](https://github.com/devploit)
