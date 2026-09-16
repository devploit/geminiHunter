# Bypass behavior

When a key returns **403 Forbidden**, the active bypass engine builds candidate domains and browser
contexts from the target, source URLs, and Google web origins, then runs
deduplicated probes and batches until the first useful result or until the
4-second bypass budget is exhausted.

The real technique names emitted in JSON are dynamic. They use these prefixes:

| Prefix | What it tests |
|--------|---------------|
| `probe:browser-ref-models` | Browser-like `Origin` / `Referer` headers against `GET /models` |
| `probe:header-browser-models` | Same browser-like probe with the key sent through `x-goog-api-key` |
| `probe:query-generate` | `POST generateContent` with the key in the query string |
| `probe:query-browser-generate` | Browser-like `POST generateContent` with host-forwarding headers |
| `common-referer:models:<referer>` | Common hard-coded `Referer` values against `GET /models` |
| `common-referer:files:<referer>` | Common hard-coded `Referer` values against `GET /files` |
| `browser:models:<referer>` | Source, target, or Google-derived `Referer` / `Origin` against `GET /models` |
| `browser:generate:<model>:<referer>` | Browser-like `POST generateContent` for priority Gemini models |
| `browser:count:<model>:<referer>` | Browser-like `POST countTokens` for priority Gemini models |
| `origin-only:<domain>` | Target-derived `Origin` and `Referer` only |
| `host-override:<domain>` | `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `Forwarded` override |
| `host-override-generate:<domain>` | Host override plus `POST generateContent` |
| `sdk:models:<client>` | SDK-like `X-Goog-Api-Client` or `User-Agent` against `GET /models` |
| `sdk:generate:<client>` | SDK-like headers plus `POST generateContent` |
| `endpoint:models:<api_version>` | `GET /models` across supported API versions |
| `endpoint:generate:<api_version>:<model>` | `POST generateContent` across API versions and priority models |
| `endpoint:count:<api_version>:<model>` | `POST countTokens` across API versions and priority models |
| `endpoint:stream:<api_version>` | `POST streamGenerateContent` |
| `endpoint:embed:<api_version>` | `POST embedContent` |

Candidate contexts include source URL origins, full source URLs as referers,
target domains, expanded target-domain variants (`app.`, `api.`, `www.`, `m.`),
and Google web origins such as AI Studio, Cloud Console, `ai.google.dev`,
MakerSuite, and Google Search. The active engine also tries common standalone
referers, including raw `127.0.0.1`, `localhost`, localhost URL variants,
`https://googleapis.com`, and `https://example.com`.

**200** responses are reported as successful bypasses. A **429** candidate is
rechecked twice: it becomes `bypassed` only after a 200 response, otherwise it
remains `rate_limited`. Rate limiting is not proof that content generation works. A 403 that changes
from `API_KEY_HTTP_REFERRER_BLOCKED` to another reason such as
`SERVICE_DISABLED` is recorded as permission progress with
`bypass_status_code: 403` and `error_reason: "SERVICE_DISABLED"`, but it is not
counted as a working bypass because the Gemini API call still cannot be used.


## Adding custom bypass attempts

The legacy `@bypass_strategy` registry still exists in
`src/geminihunter/validation/bypass.py`, but the active `BypassEngine.run()` flow
uses explicit probe and batch builders. To make a bypass active, add attempts to
one of these methods:

| Method | Use it for |
|--------|------------|
| `_classification_probes` | Cheap first-pass probes that should run before the full batches |
| `_common_referrer_attempts` | Hard-coded standalone `Referer` values such as localhost variants |
| `_contextual_referrer_attempts` | Source, target, and Google-derived `Origin` / `Referer` contexts |
| `_host_override_attempts` | Host and forwarded-host header combinations |
| `_sdk_attempts` | SDK-like client headers and user agents |
| `_endpoint_matrix_attempts` | API version, model, and endpoint combinations |

Update this document and add a focused unit test whenever a new active bypass
family is introduced.


[Back to the README](../README.md)
