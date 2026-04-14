"""Transport-layer helpers and error classification."""

from dataclasses import dataclass

import httpx


@dataclass
class TransportIssue:
    kind: str
    detail: str
    retryable: bool


def classify_transport_error(err: Exception) -> TransportIssue:
    """Classify transport errors into retryable/non-retryable buckets."""
    text = str(err)
    lowered = text.lower()

    if "certificate verify failed" in lowered or "hostname mismatch" in lowered:
        return TransportIssue("tls", text, False)
    if "name or service not known" in lowered or "nodename nor servname provided" in lowered:
        return TransportIssue("dns", text, False)
    if "temporary failure in name resolution" in lowered:
        return TransportIssue("dns", text, True)
    if isinstance(
        err,
        (
            httpx.ConnectTimeout,
            httpx.ReadTimeout,
            httpx.WriteTimeout,
            httpx.PoolTimeout,
        ),
    ):
        return TransportIssue("timeout", text, True)
    if isinstance(err, httpx.ConnectError):
        return TransportIssue("connect", text, True)
    if isinstance(err, httpx.ReadError):
        return TransportIssue("read", text, True)
    return TransportIssue("network", text, True)
