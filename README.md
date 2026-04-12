<h1 align="center">geminiHunter</h1>

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

- **Discovery** -- Crawls domains/subdomains extracting API keys from HTML, JS files, source maps (`.js.map`), webpack chunks, and Wayback Machine historical JS. Detects `<link rel="preload/modulepreload">` scripts, Next.js/Nuxt.js/Firebase data files, and parses `sourceMappingURL` comments
- **APK Scanning** -- Decompiles Android APK/XAPK files to extract API keys. Uses `jadx` when available for full Java source decompilation, falls back to ZIP extraction with string extraction from `.dex` and `resources.arsc` (no external tools required)
- **JS Deobfuscation** -- Beautifies minified JS before regex extraction to catch split/concatenated keys
- **Key Extraction** -- 10 regex patterns covering direct matches, string concatenation, multi-part splits, array joins, template literals, reversed keys, fallback/default values, hex-encoded prefixes, and base64-encoded keys
- **Validation** -- Tests extracted keys against the Google Gemini API
- **403 Bypass Engine** -- 16 bypass strategies generating 73 attempts per key:
  - Referer rotation (Google, target domain, common values)
  - Origin header manipulation
  - X-Forwarded-For / X-Real-IP spoofing
  - API version bruteforce (v1, v1beta, v1beta2, v1beta3)
  - Endpoint switching (models, generateContent, embedContent, countTokens, streamGenerateContent, tunedModels, cachedContents, files, corpora)
  - HTTP method switching
  - `x-goog-api-key` header authentication (key via header instead of query param)
  - Google SDK header/User-Agent impersonation
  - Combo strategies (Referer + version, Referer + endpoint, header + Referer + Origin)
- **Key Intelligence** -- Enumerates available models, fine-tuned models, billing status, quota, GCP project ID and project name
- **OPSEC** -- Proxy rotation, rate limiting, User-Agent rotation, configurable delays
- **Flexible Input** -- Domains, files, stdin pipe, scan JSON (gengar-style), direct API keys, or APK/XAPK files
- **Pipeline-friendly** -- JSON output, exit codes, stdin/stdout compatible with recon tools

## Installation

```bash
git clone https://github.com/devploit/geminiHunter.git
cd geminiHunter
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

**Optional**: Install [jadx](https://github.com/skylot/jadx) for better APK decompilation results:

```bash
# macOS
brew install jadx

# Linux
sudo apt install jadx
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

### APK mode -- scan Android apps

```bash
# Single APK
geminihunter --apk app.apk

# XAPK (auto-extracts inner APKs)
geminihunter --apk app.xapk

# Multiple APKs
geminihunter --apk base.apk --apk split_config.apk

# APK + web targets
geminihunter --apk app.apk example.com

# APK + direct key validation
geminihunter --apk app.apk -k AIzaSyEXTRA_KEY_TO_CHECK
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
  --apk PATH                     APK/XAPK file(s) to decompile and scan (repeatable)
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
Mode 1 (Discovery):                  Mode 2 (Direct -k):     Mode 3 (APK):
  Targets (stdin/file/args/json)       Keys (--key/file/stdin)   APK/XAPK files (--apk)
      |                                    |                        |
  Discovery (crawl, wayback,               |                   Decompile (jadx or ZIP)
             sourcemaps, webpack,          |                   Extract sources
             preload, frameworks)          |                        |
      |                                    |                        |
  Extraction (deobfuscate + 10 regex       |                   Extraction (10 regex
              patterns, dedup)             |                    patterns, dedup)
      \_______________  __________________/___________________/
                      \/
                 Validation  -- test against Gemini API
                      |
                 Bypass Engine  -- 16 strategies, 73 attempts
                      |
                 Intelligence  -- models, tuned models, billing,
                                  quota, project ID/name
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

# APK from app store + web targets
geminihunter --apk com.target.app.apk -f subs.txt --json -o full_scan.json
```

**Exit codes**: `0` if valid/bypassed keys found, `1` otherwise.

## Bypass techniques

| # | Technique | Description |
|---|-----------|-------------|
| 1 | `referer_google` | Referer: google.com, aistudio, cloud console, ai.google.dev |
| 2 | `referer_target` | Referer: target domain variants (https, http, www) |
| 3 | `referer_common` | Referer: googleapis.com, localhost, empty |
| 4 | `origin_header` | Origin header manipulation (Google, null, target) |
| 5 | `xff_bypass` | X-Forwarded-For / X-Real-IP with internal IPs |
| 6 | `api_version` | API version bruteforce (v1, v1beta, v1beta2, v1beta3) |
| 7 | `endpoint_switch` | Different endpoints (models, generateContent, embedContent, countTokens) |
| 8 | `method_switch` | HTTP method switching (POST, OPTIONS, HEAD) |
| 9 | `combo_referer_version` | Referer + API version combinations |
| 10 | `combo_referer_endpoint` | Referer + generateContent endpoint |
| 11 | `api_key_header` | Key via `x-goog-api-key` header instead of `?key=` query param |
| 12 | `stream_endpoint` | Streaming endpoint (`streamGenerateContent`) |
| 13 | `alt_endpoint` | Less common endpoints (tunedModels, cachedContents, files, corpora) |
| 14 | `combo_header_referer` | Triple: `x-goog-api-key` header + Referer + Origin |
| 15 | `sdk_headers` | `X-Goog-Api-Client` mimicking official Google SDKs |
| 16 | `sdk_ua` | User-Agent strings from official Google SDK clients |

## Extraction patterns

| Pattern | Example |
|---------|---------|
| Direct match | `AIzaSyABC...XYZ` |
| String concatenation | `"AIzaSy" + "suffix"` |
| Multi-part split | `"AIzaSy" + "part1" + "part2" + "part3"` |
| Array join | `["AIzaSy","rest"].join("")` |
| Template literal | `` `AIzaSy${"suffix"}` `` |
| Reversed key | `"76543...ySzIA"` |
| Fallback/default | `getEnv() \|\| "AIzaSy..."` |
| Hex-encoded prefix | `"\x41\x49\x7a\x61\x53\x79" + suffix` |
| Base64-encoded | `"QUl6YVN5..."` (decoded to `AIzaSy...`) |

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
