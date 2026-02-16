"""
Secret scrubbing utilities for OpenClaw Scanner.

Redacts secrets (API keys, tokens, passwords, connection strings) from text,
URLs, and argument dicts before they reach stdout or the API endpoint.
"""

import re
from typing import Any, Callable, Dict, List, Union
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

REDACTED = "***REDACTED***"

# ---------------------------------------------------------------------------
# Tier 1 — Known secret prefixes (high confidence, standalone matches)
# ---------------------------------------------------------------------------

_TIER1_PATTERNS: List[re.Pattern[str]] = [
    # OpenAI keys: sk-proj-... or sk-<40+ chars>
    re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    # Anthropic keys
    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    # AWS access key IDs
    re.compile(r"AKIA[0-9A-Z]{16}"),
    # GitHub tokens
    re.compile(r"gh[posr]_[A-Za-z0-9_]{20,}"),
    # GitLab personal access tokens
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),
    # Slack tokens
    re.compile(r"xox[bpoas]-[A-Za-z0-9-]{10,}"),
    # Stripe keys (also covers Clerk sk_live_ pattern)
    re.compile(r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}"),
    # Google API keys
    re.compile(r"AIza[A-Za-z0-9_-]{30,}"),
    # Hugging Face tokens
    re.compile(r"hf_[A-Za-z0-9]{20,}"),
    # npm tokens
    re.compile(r"npm_[A-Za-z0-9]{20,}"),
    # JWTs (three dot-separated base64url segments, first starts with eyJ)
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    # SendGrid API keys (SG.xxx.yyy)
    re.compile(r"SG\.[A-Za-z0-9_.-]{20,}"),
    # Twilio API Key SID
    re.compile(r"SK[0-9a-fA-F]{32}"),
    # Databricks tokens
    re.compile(r"dapi[0-9a-fA-F]{32,}"),
    # DigitalOcean tokens
    re.compile(r"dop_v1_[A-Fa-f0-9]{64}"),
    # Shopify tokens (shpat_, shpca_, shppa_)
    re.compile(r"shp(?:at|ca|pa)_[A-Fa-f0-9]{32,}"),
    # Atlassian API tokens
    re.compile(r"ATATT[A-Za-z0-9_-]{20,}"),
    # PyPI tokens
    re.compile(r"pypi-[A-Za-z0-9_-]{20,}"),
    # Hashicorp Vault tokens
    re.compile(r"hvs\.[A-Za-z0-9_-]{20,}"),
    # Grafana cloud/service account tokens
    re.compile(r"gl(?:c|sa)_[A-Za-z0-9_-]{20,}"),
    # Linear API keys
    re.compile(r"lin_api_[A-Za-z0-9]{20,}"),
    # PlanetScale tokens
    re.compile(r"pscale_tkn_[A-Za-z0-9_-]{20,}"),
    # Postman API keys
    re.compile(r"PMAK-[A-Za-z0-9_-]{20,}"),
    # Pulumi tokens
    re.compile(r"pul-[A-Za-z0-9]{20,}"),
    # Doppler tokens
    re.compile(r"dp\.st\.[A-Za-z0-9_-]{20,}"),
    # Notion tokens
    re.compile(r"ntn_[A-Za-z0-9]{20,}"),
    # Telegram bot tokens
    re.compile(r"\d{8,}:AA[A-Za-z0-9_-]{30,}"),
    # Private key blocks (PEM)
    re.compile(r"-----BEGIN\s+[\w\s]*PRIVATE KEY-----"),
    # Generic live_/test_ prefixed long keys (e.g. TheCatAPI)
    re.compile(r"(?:live|test)_[A-Za-z0-9]{30,}"),
    # Vercel tokens
    re.compile(r"vercel_[A-Za-z0-9_-]{20,}"),
    # Resend tokens
    re.compile(r"re_[A-Za-z0-9]{20,}"),
    # Figma tokens
    re.compile(r"figd_[A-Za-z0-9_-]{20,}"),
]

# ---------------------------------------------------------------------------
# Tier 2 — Contextual patterns (need surrounding context)
# ---------------------------------------------------------------------------

_TIER2_PATTERNS: List[tuple[re.Pattern[str], Union[str, Callable]]] = [
    # Env var assignments: API_KEY=xxx, export TOKEN="xxx"
    (
        re.compile(
            r"""(?:export\s+)?"""
            r"""(?:"""
            r"""[A-Za-z_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)"""
            r""")[A-Za-z0-9_]*"""
            r"""\s*=\s*"""
            r"""(?:["']?)(\S+?)(?:["']?)(?:\s|$)""",
            re.IGNORECASE,
        ),
        lambda m: m.group(0).replace(m.group(1), REDACTED),
    ),
    # Bearer / Basic auth headers
    (
        re.compile(r"((?:Bearer|Basic)\s+)\S+", re.IGNORECASE),
        lambda m: m.group(1) + REDACTED,
    ),
    # Connection strings with embedded passwords: postgres://user:pass@host
    (
        re.compile(r"((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:]+:)([^@]+)(@)"),
        lambda m: m.group(1) + REDACTED + m.group(3),
    ),
    # CLI password/token flags: --password value, --token=value, -p value
    (
        re.compile(
            r"((?:--?(?:password|passwd|token|api[_-]?key|secret|private[_-]?key|access[_-]?key))"
            r"""(?:\s*[=\s]\s*))"""
            r"""(?:["']?)(\S+?)(?:["']?)(?:\s|$)""",
            re.IGNORECASE,
        ),
        lambda m: m.group(1) + REDACTED + m.group(0)[m.end(2) - m.start(0):],
    ),
    # Header values: -H "Authorization: value" or --header "Authorization: value"
    (
        re.compile(
            r"""((?:-H|--header)\s+["'](?:Authorization|X-Api-Key|X-Auth-Token)\s*:\s*)([^"']+)(["'])""",
            re.IGNORECASE,
        ),
        lambda m: m.group(1) + REDACTED + m.group(3),
    ),
    # JSON secret fields: "api_key": "value", "token": "value", etc.
    (
        re.compile(
            r"""("(?:api_key|apikey|api-key|token|secret|password|passwd|access_token|auth_token|client_secret|private_key|secret_key|credentials|authorization)"\s*:\s*")([^"]+)(")""",
            re.IGNORECASE,
        ),
        lambda m: m.group(1) + REDACTED + m.group(3),
    ),
    # curl -u user:pass (basic auth shorthand)
    (
        re.compile(
            r"""(curl\s+.*?-u\s+)(\S+:\S+)""",
            re.IGNORECASE,
        ),
        lambda m: m.group(1) + REDACTED,
    ),
    # Generic colon-separated key-value with sensitive key name: token:value, api_key:value
    (
        re.compile(
            r"""(?<![/\w])(?:token|api_key|apikey|api-key|secret|password|auth_token|access_token):([A-Za-z0-9_-]{8,})""",
            re.IGNORECASE,
        ),
        lambda m: m.group(0).replace(m.group(1), REDACTED),
    ),
]

# ---------------------------------------------------------------------------
# URL-specific sensitive query param names
# ---------------------------------------------------------------------------

_SENSITIVE_QUERY_PARAMS = frozenset({
    "api_key", "apikey", "api-key",
    "token", "access_token", "auth_token",
    "secret", "secret_key",
    "password", "passwd",
    "key", "private_key",
    "client_secret",
    "authorization",
    "refresh_token", "session_token",
    "auth", "credentials",
})


def scrub_text(text: str) -> str:
    """Apply all regex patterns to redact secrets from *text*.

    Tier 1 patterns are applied first (standalone high-confidence matches),
    then Tier 2 patterns (contextual).
    """
    # Tier 1
    for pattern in _TIER1_PATTERNS:
        text = pattern.sub(REDACTED, text)

    # Tier 2
    for pattern, replacement in _TIER2_PATTERNS:
        if callable(replacement):
            text = pattern.sub(replacement, text)
        else:
            text = pattern.sub(replacement, text)

    return text


def scrub_url(url: str) -> str:
    """URL-aware scrubber: redacts sensitive query params and userinfo."""
    if not url:
        return url

    try:
        parsed = urlparse(url)
    except Exception:
        # If URL parsing fails, fall back to text scrubbing
        return scrub_text(url)

    # If it doesn't look like a real URL, fall back to text scrubbing
    if not parsed.scheme or not parsed.netloc:
        return scrub_text(url)

    changed = False

    # Scrub userinfo (user:pass@host)
    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, _, hostinfo = netloc.rpartition("@")
        if ":" in userinfo:
            user, _ = userinfo.split(":", 1)
            netloc = f"{user}:{REDACTED}@{hostinfo}"
            changed = True

    # Scrub sensitive query params
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        new_params: Dict[str, List[str]] = {}
        for key, values in params.items():
            if key.lower() in _SENSITIVE_QUERY_PARAMS:
                new_params[key] = [REDACTED] * len(values)
                changed = True
            else:
                new_params[key] = values

        if changed:
            # Use quote_via to prevent percent-encoding the REDACTED marker
            new_query = urlencode(new_params, doseq=True, quote_via=lambda s, safe='', encoding=None, errors=None: s)
            return urlunparse(parsed._replace(netloc=netloc, query=new_query))

    if changed:
        return urlunparse(parsed._replace(netloc=netloc))

    return url


def scrub_arguments(args: Any) -> Any:
    """Walk an argument dict/list and apply scrubbing to string values.

    Returns a new structure (no mutation of the original).
    Non-string, non-dict, non-list values pass through unchanged.
    """
    if isinstance(args, dict):
        result: Dict[str, Any] = {}
        for key, value in args.items():
            if isinstance(value, str):
                # Always apply text scrubbing first (catches headers, tokens, etc.),
                # then additionally apply URL scrubbing for URL-shaped values.
                scrubbed = scrub_text(value)
                if scrubbed.startswith(("http://", "https://")) or "://" in scrubbed:
                    scrubbed = scrub_url(scrubbed)
                result[key] = scrubbed
            elif isinstance(value, (dict, list)):
                result[key] = scrub_arguments(value)
            else:
                result[key] = value
        return result

    if isinstance(args, list):
        return [scrub_arguments(item) for item in args]

    if isinstance(args, str):
        scrubbed = scrub_text(args)
        if scrubbed.startswith(("http://", "https://")) or "://" in scrubbed:
            scrubbed = scrub_url(scrubbed)
        return scrubbed

    return args
