<p align="center">
  <img src="assets/logo.png" alt="geminiHunter" width="200">
</p>

<h1 align="center">geminiHunter</h1>

<p align="center">
  <b>Discover, validate, and bypass Google Gemini API keys from web targets and Android apps</b>
</p>

<p align="center">
  <a href="https://github.com/devploit/geminiHunter/releases"><img src="https://img.shields.io/github/v/release/devploit/geminiHunter?style=flat-square" alt="Release"></a>
  <a href="https://github.com/devploit/geminiHunter/blob/main/LICENSE"><img src="https://img.shields.io/github/license/devploit/geminiHunter?style=flat-square" alt="License"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" alt="Python"></a>
  <a href="https://github.com/devploit/geminiHunter"><img src="https://img.shields.io/github/stars/devploit/geminiHunter?style=flat-square" alt="Stars"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#bypass-techniques">Bypass Techniques</a> &bull;
  <a href="#apk-scanning">APK Scanning</a> &bull;
  <a href="#integration">Integration</a>
</p>

---

## What it does

geminiHunter crawls web targets and decompiles Android apps looking for exposed Google Gemini API keys. When a key returns 403 Forbidden, it runs **16 bypass strategies** (73 attempts) to find a working combination. For every valid or bypassed key, it gathers intelligence: available models, fine-tuned models, billing status, quota, GCP project info, and key restriction type.

## Quick Start

```bash
# One-liner install (recommended)
pipx install git+https://github.com/devploit/geminiHunter.git

# Scan a domain
geminihunter example.com

# Check a key you already found
geminihunter -k AIzaSyYOUR_KEY_HERE

# Scan an APK
geminihunter --apk app.apk
```

## Installation

### Option 1: pipx (recommended)

One command, isolated environment, binary on PATH automatically:

```bash
pipx install git+https://github.com/devploit/geminiHunter.git
```

> Don't have pipx? Install it with `pip install pipx && pipx ensurepath` or `brew install pipx`.

Update to latest version:

```bash
pipx upgrade geminihunter
```

### Option 2: pip

```bash
pip install git+https://github.com/devploit/geminiHunter.git
```

### Option 3: From source (development)

```bash
git clone https://github.com/devploit/geminiHunter.git && cd geminiHunter
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Optional: jadx for APK scanning

Install [jadx](https://github.com/skylot/jadx) for full Java source recovery from APKs:

```bash
# macOS
brew install jadx

# Linux
sudo apt install jadx
```

Without jadx, APK scanning still works using ZIP extraction + binary string extraction from `.dex` and `resources.arsc`. No external tools required.

## Usage

### Discovery mode -- crawl targets for keys

```bash
# Single domain
geminihunter example.com

# Multiple domains
geminihunter app.example.com api.example.com cdn.example.com

# File with targets (one per line, # comments supported)
geminihunter -f subdomains.txt

# Scan JSON (gengar-style)
geminihunter -sj scan-results.json

# Pipe from recon tools
subfinder -d example.com | httpx -silent | geminihunter

# Control crawl depth
geminihunter example.com --depth 3

# Skip Wayback Machine (faster, less thorough)
geminihunter example.com --no-wayback
```

### APK mode -- decompile and scan Android apps

```bash
# Single APK
geminihunter --apk app.apk

# XAPK (auto-extracts inner APKs)
geminihunter --apk app.xapk

# Multiple APKs (split APKs)
geminihunter --apk base.apk --apk split_config.apk

# APK + web targets (scan both)
geminihunter --apk app.apk -f subdomains.txt

# APK + additional keys to validate
geminihunter --apk app.apk -k AIzaSyEXTRA_KEY
```

### Key-check mode -- validate keys directly

```bash
# Single key
geminihunter -k AIzaSyYOUR_KEY_HERE

# Multiple keys (comma-separated)
geminihunter -k key1,key2,key3

# From file
geminihunter --key-file found_keys.txt

# From stdin
echo "AIzaSy..." | geminihunter -k -

# Skip bypass attempts (faster)
geminihunter -k AIzaSy... --no-bypass
```

### Output options

```bash
# JSON output to stdout
geminihunter example.com --json

# Save to file (JSON auto-detected when using -o)
geminihunter example.com -o results.json

# Include curl commands to reproduce each finding
geminihunter example.com --evidence

# Quiet mode (no banner, no progress -- only results)
geminihunter example.com -q --json
```

### OPSEC options

```bash
# Single proxy
geminihunter example.com --proxy http://127.0.0.1:8080

# Proxy rotation (file with proxy URLs, one per line)
geminihunter -f targets.txt --proxy proxies.txt

# Rate limiting
geminihunter -f targets.txt --rate-limit 5

# Fixed delay between requests
geminihunter example.com --delay 0.5

# Custom User-Agent
geminihunter example.com --user-agent "Mozilla/5.0 (Macintosh; ...)"

# Lower concurrency for stealth
geminihunter -f targets.txt --concurrency 5 --rate-limit 2
```

### All options

```
Usage: geminihunter [OPTIONS] [TARGETS]...

Options:
  -f, --file PATH                 File with targets (one per line)
  -sj, --scan-json PATH          Scan JSON file (gengar-style)
  -k, --key TEXT                  API key(s) (comma-separated, or - for stdin)
  --key-file PATH                 File with API keys (one per line)
  --apk PATH                     APK/XAPK file(s) to decompile and scan
  --depth INTEGER                 Crawl depth  [default: 2]
  --wayback / --no-wayback        Include Wayback Machine JS  [default: wayback]
  --sourcemaps / --no-sourcemaps  Chase .js.map files  [default: sourcemaps]
  --bypass / --no-bypass          Run 403 bypass engine  [default: bypass]
  --proxy TEXT                    Proxy URL or file with proxy list
  --rate-limit FLOAT              Max requests/second  [default: 10.0]
  --delay FLOAT                   Fixed delay between requests  [default: 0.0]
  --timeout FLOAT                 HTTP timeout (seconds)  [default: 15.0]
  --concurrency INTEGER           Max concurrent requests  [default: 20]
  --user-agent TEXT               Custom User-Agent or "rotate"  [default: rotate]
  -o, --output PATH               Write results to file
  --json                          Output as JSON
  -v, --verbose                   Verbose logging
  -q, --quiet                     Suppress banner and progress
  --evidence                      Include curl PoC commands
  --version                       Show version and exit
  --help                          Show this message and exit
```

## How it works

### Architecture

```
Target Input                     Key Input                APK Input
(domains, files, stdin, json)    (--key, --key-file)      (--apk .apk/.xapk)
         |                              |                         |
   +-----v--------+                     |                  +------v-------+
   |  Discovery   |                     |                  |   Decompile  |
   |  - Crawl     |                     |                  |   jadx/ZIP   |
   |  - Wayback   |                     |                  +------+-------+
   |  - Sourcemaps|                     |                         |
   |  - Webpack   |                     |                  +------v------+
   |  - Preload   |                     |                  |  Scan files  |
   +-----+--------+                     |                  |  .java .xml  |
         |                              |                  |  .dex .arsc  |
   +-----v--------+                     |                  +------+------+
   |  Extraction  |                     |                         |
   |  10 patterns |<----------------------------------------------+
   |  deobfuscate |
   |  dedup       |
   +-----+--------+
         |
         +<--- direct keys (--key) ----+
         |
   +-----v--------+
   |  Validation  |  GET /v1beta/models?key=...
   +-----+--------+
         |
    200? +--> VALID
    403? +--> Bypass Engine (16 strategies, 73 attempts)
         |      200/429? --> BYPASSED
         |      all fail --> FORBIDDEN
    4xx? +--> INVALID
         |
   +-----v--------+
   | Intelligence |  (only for VALID / BYPASSED)
   |  - Models    |  GET /v1beta/models
   |  - Tuned     |  GET /v1beta/tunedModels
   |  - Billing   |  POST generateContent
   |  - Project   |  Error response + headers
   |  - Restrict  |  Referrer/app restriction probe
   +-----+--------+
         |
   +-----v--------+
   |    Output    |
   |  Rich table  |
   |  JSON        |
   |  Curl PoCs   |
   +--------------+
```

### Discovery sources

| Source | Description |
|--------|-------------|
| **HTML inline** | `<script>` tags in crawled HTML pages |
| **JS files** | External `.js` files referenced by `<script src>`, `<link preload>`, or detected in HTML |
| **Source maps** | `.js.map` files (via `{url}.map` convention and `sourceMappingURL` comments) |
| **Webpack chunks** | Lazy-loaded chunks discovered from webpack runtime patterns |
| **Wayback Machine** | Historical JS snapshots from `web.archive.org` CDX API |
| **Framework files** | Next.js (`/_next/data/`, `/_next/static/`), Nuxt.js (`/_nuxt/`), Firebase (`/__/firebase/`) |
| **APK sources** | Decompiled Java/Kotlin, decoded XML resources, `assets/`, binary strings from `.dex` |

### Extraction patterns

Keys are matched using 10 regex patterns that cover common obfuscation techniques:

| Pattern | What it catches | Example |
|---------|----------------|---------|
| Direct match | Plain API keys | `"AIzaSyABC...XYZ"` |
| String concat | Two-part split | `"AIzaSy" + "suffix..."` |
| Multi-part split | 3+ concatenated parts | `"AIzaSy" + "abc" + "def" + "ghi"` |
| Array join | Array-based construction | `["AIzaSy","rest"].join("")` |
| Template literal | JS template syntax | `` `AIzaSy${"suffix"}` `` |
| Reversed | Key stored backwards | `"...ZYXySzIA"` |
| Fallback value | Default/fallback assignments | `getEnv() \|\| "AIzaSy..."` |
| Hex-encoded | Prefix as hex escapes | `"\x41\x49\x7a\x61\x53\x79..."` |
| Base64-encoded | Full key base64'd | `"QUl6YVN5..."` (decodes to `AIzaSy...`) |

Keys with fewer than 5 unique characters in the suffix are automatically filtered as placeholders.

## Bypass techniques

When a key returns **403 Forbidden**, the bypass engine tests 16 strategies concurrently, exiting on the first success:

| # | Strategy | Attempts | Technique |
|---|----------|----------|-----------|
| 1 | `referer_google` | 7 | Referer from google.com, aistudio, cloud console, ai.google.dev |
| 2 | `referer_target` | 4 | Referer set to target domain variants (https, http, www) |
| 3 | `referer_common` | 7 | Referer from googleapis.com, localhost variants, empty |
| 4 | `origin_header` | 5 | Origin header: Google domains, null, target domain |
| 5 | `xff_bypass` | 6 | X-Forwarded-For + X-Real-IP with internal IPs (127.0.0.1, 10.x, etc.) |
| 6 | `api_version` | 4 | API version rotation: v1, v1beta, v1beta2, v1beta3 |
| 7 | `endpoint_switch` | 4 | Alternate endpoints: generateContent, embedContent, countTokens |
| 8 | `method_switch` | 3 | HTTP method: POST, OPTIONS, HEAD |
| 9 | `combo_referer_version` | 8 | Google Referer + API version combinations |
| 10 | `combo_referer_endpoint` | 3 | Google Referer + generateContent with JSON body |
| 11 | `api_key_header` | 4 | Key via `x-goog-api-key` header (no `?key=` in URL) |
| 12 | `stream_endpoint` | 2 | `streamGenerateContent` streaming endpoint |
| 13 | `alt_endpoint` | 4 | tunedModels, cachedContents, files, corpora |
| 14 | `combo_header_referer` | 6 | Triple: `x-goog-api-key` + Referer + Origin (with/without body) |
| 15 | `sdk_headers` | 3 | `X-Goog-Api-Client` mimicking JS/Python/Go SDKs |
| 16 | `sdk_ua` | 3 | User-Agent from official Google SDK clients |

Both **200** and **429** (rate-limited) responses are treated as successful bypasses -- 429 confirms the key is accepted, just throttled.

## APK scanning

The `--apk` flag accepts `.apk` and `.xapk` files. XAPK files (ZIP bundles containing multiple APKs) are automatically unpacked.

### Decompilation engines

| Engine | Condition | What it scans |
|--------|-----------|--------------|
| **jadx** | Auto-detected if `jadx` is in PATH | Full Java/Kotlin source, decoded XML resources, manifests |
| **ZIP fallback** | No external tools needed | Text files in `assets/`, string extraction from `.dex` and `resources.arsc` |

With jadx, the tool recovers full source code, catching keys built via string concatenation, config classes, BuildConfig fields, and obfuscated constructions. The ZIP fallback extracts ASCII strings >= 39 characters from binary files, which catches any hardcoded full key.

### What it finds inside APKs

- API keys in `assets/` configs (JSON, XML, YAML, properties)
- Keys in decompiled Java/Kotlin source (string constants, BuildConfig, flavors)
- Keys in decoded `res/values/strings.xml` (via jadx or `resources.arsc` binary extraction)
- Keys in bundled web assets (`assets/www/`, hybrid app JS bundles)
- Keys in Firebase configuration files
- Base64/hex-obfuscated keys in any of the above

## Key intelligence

For every **valid** or **bypassed** key, geminiHunter gathers:

| Field | Source | Description |
|-------|--------|-------------|
| **Available models** | `GET /v1beta/models` | Full list of models the key can access |
| **Fine-tuned models** | `GET /v1beta/tunedModels` | Custom models (indicates training data exposure) |
| **GCP Project ID** | Error responses + headers | Numeric project identifier |
| **Project name** | `x-goog-api-resource-name` header | Human-readable project name |
| **Billing status** | `POST generateContent` | Whether billing is active (can make real API calls) |
| **Quota** | Response headers | Remaining and total quota if available |
| **Restrictions** | Bypass analysis + probing | Detects if the key has referrer, application, or no restrictions |

Fine-tuned models are highlighted in red in the output -- they indicate the organization has uploaded custom training data, which significantly increases the impact of the finding.

Unrestricted keys are flagged in red -- they have no application restrictions (no referrer, IP, or app binding), making them usable from anywhere.

## JSON output

With `--json`, results are written as a structured JSON object:

```json
{
  "targets_scanned": ["example.com"],
  "sources_crawled": 312,
  "keys_found": 2,
  "keys_valid": 1,
  "keys_bypassed": 1,
  "keys_forbidden": 0,
  "keys_invalid": 0,
  "duration_seconds": 4.82,
  "phase_timings": {
    "discovery": 2.1,
    "extraction": 0.3,
    "validation": 1.8,
    "intelligence": 0.6
  },
  "results": [
    {
      "key": "AIzaSy...",
      "status": "valid",
      "target_domain": "example.com",
      "sources": ["https://cdn.example.com/app.js"],
      "bypass": null,
      "available_models": ["gemini-2.0-flash", "gemini-2.5-pro", "..."],
      "tuned_models": [],
      "project_id": "123456789",
      "project_name": "my-project",
      "billing_enabled": true,
      "quota_remaining": null,
      "quota_limit": null,
      "curl_commands": ["curl -s 'https://generativelanguage.googleapis.com/...'"]
    }
  ]
}
```

Parse with jq:

```bash
# Extract working keys
geminihunter -f subs.txt -q --json | jq -r '.results[] | select(.status == "valid" or .status == "bypassed") | .key'

# Count models per key
geminihunter -k KEY --json | jq '.results[] | {key: .key[0:16], models: (.available_models | length), billing: .billing_enabled}'

# Get bypass technique used
geminihunter -k KEY --json | jq '.results[] | select(.bypass) | {key: .key[0:16], technique: .bypass.technique, status: .bypass.bypass_status_code}'
```

## Config file

Create `.geminihunterrc` or `.geminihunter.toml` in the current directory or home directory to set defaults:

```toml
# .geminihunter.toml
depth = 3
wayback = true
sourcemaps = true
bypass = true
rate-limit = 5.0
delay = 0.2
timeout = 20.0
concurrency = 10
user-agent = "rotate"
evidence = true
```

CLI arguments always override config file values.

## Integration with recon pipelines

```bash
# Full recon chain: subfinder -> httpx -> geminiHunter
subfinder -d target.com -silent | httpx -silent | geminihunter --json -o results.json

# With proxy rotation for stealth
geminihunter -f targets.txt --proxy proxies.txt --rate-limit 3 --delay 0.5

# Parallel with other key scanners
geminihunter -f subs.txt -q --json | jq -r '.results[] | select(.status != "invalid") | .key' >> all_keys.txt

# APK from app store + full web scan
geminihunter --apk com.target.app.apk -f subs.txt --evidence --json -o full_report.json

# Quick key check from clipboard
pbpaste | geminihunter -k - --no-bypass --json
```

**Exit codes**: `0` if valid/bypassed keys found, `1` otherwise. Use this in CI/CD or shell conditionals.

## Adding custom bypass strategies

The bypass engine uses an auto-registry decorator. Add a new strategy in `src/geminihunter/validation/bypass.py`:

```python
@bypass_strategy
class MyBypass(BypassStrategy):
    name = "my_bypass"

    def generate_attempts(self, key: str, target_domain: str) -> list[BypassAttempt]:
        return [
            BypassAttempt(
                technique_name="my_bypass:custom",
                headers={"X-Custom": "value"},
            ),
            # Key via header instead of query param:
            BypassAttempt(
                technique_name="my_bypass:header",
                headers={"x-goog-api-key": key, "X-Custom": "value"},
                key_in_header=True,
            ),
        ]
```

No other file needs modification -- the `@bypass_strategy` decorator auto-registers it.

## Project structure

```
src/geminihunter/
  cli.py                    # Click CLI, argument parsing, config file loading
  config.py                 # Global Config dataclass
  models.py                 # Pydantic models (SourceType, KeyStatus, ScanResult, etc.)
  pipeline.py               # Main pipeline orchestrator

  discovery/
    crawler.py              # Web crawler (HTML, JS, preload, framework files)
    wayback.py              # Wayback Machine CDX integration
    sourcemaps.py           # .js.map discovery and sourcesContent extraction
    webpack.py              # Webpack lazy-loaded chunk finder
    apk.py                  # APK/XAPK decompilation and scanning

  extraction/
    patterns.py             # 10 compiled regex patterns
    extractor.py            # Key extraction and deduplication engine
    deobfuscator.py         # JS beautification for split key recovery

  validation/
    validator.py            # Key validation orchestrator
    bypass.py               # 16 auto-registered bypass strategies + engine

  intelligence/
    recon.py                # Post-validation intelligence gathering

  network/
    session.py              # httpx client, proxy/UA rotation, retry logic
    ratelimit.py            # Token-bucket rate limiter

  output/
    console.py              # Rich terminal table and detail panels
    json_out.py             # JSON serialization
    evidence.py             # Curl PoC command generation
```

## Disclaimer

This tool is intended for **authorized security testing and bug bounty programs only**. Always ensure you have explicit permission before testing any target. The author is not responsible for any misuse.

## Author

[@devploit](https://github.com/devploit)
