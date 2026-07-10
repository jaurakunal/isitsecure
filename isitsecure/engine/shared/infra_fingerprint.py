"""Lightweight infrastructure fingerprinting from HTTP response headers.

Pure, dependency-free helpers that map generic CDN / edge / hosting signals in
raw response headers to provider names.  Deliberately app-agnostic: the signal
map keys off vendor-standard headers only, never app-specific routes or names.
"""

from __future__ import annotations

# Provider -> list of header signals. A signal is either:
#   ("header_name", None)          -> match if the header is present
#   ("header_name", "substr")      -> match if the header value contains substr
# Header names are matched case-insensitively; substring checks are lower-cased.
_PROVIDER_SIGNALS: dict[str, list[tuple[str, str | None]]] = {
    "Cloudflare": [
        ("cf-ray", None),
        ("cf-cache-status", None),
        ("server", "cloudflare"),
    ],
    "Vercel": [
        ("x-vercel-id", None),
        ("x-vercel-cache", None),
        ("server", "vercel"),
    ],
    "Netlify": [
        ("x-nf-request-id", None),
        ("server", "netlify"),
    ],
    "Fastly": [
        ("x-served-by", "cache-"),
        ("x-fastly-request-id", None),
        ("server", "fastly"),
    ],
    "AWS CloudFront": [
        ("x-amz-cf-id", None),
        ("x-amz-cf-pop", None),
        ("via", "cloudfront"),
    ],
    "Akamai": [
        ("x-akamai-transformed", None),
        ("akamai-grn", None),
    ],
    "GitHub Pages": [
        ("server", "github.com"),
    ],
}


def detect_providers(raw_headers: dict[str, str] | None) -> list[str]:
    """Return provider names inferred from HTTP response headers.

    Args:
        raw_headers: Response headers (header name -> value). Missing / empty
            input yields an empty list.

    Returns:
        De-duplicated provider names in a stable, deterministic order.
    """
    if not raw_headers:
        return []

    # Normalise header names to lower-case for case-insensitive lookup.
    normalized = {
        str(name).lower(): str(value)
        for name, value in raw_headers.items()
    }

    detected: list[str] = []
    for provider, signals in _PROVIDER_SIGNALS.items():
        for header_name, substr in signals:
            value = normalized.get(header_name.lower())
            if value is None:
                continue
            if substr is None or substr.lower() in value.lower():
                detected.append(provider)
                break

    return detected
