"""
PHANTOM SNARE — Argument Scrubber
Redacts sensitive values (credentials, keys, tokens) from tool arguments
BEFORE they are written to log files or sent to webhooks.

Why this exists:
  Shield mode intercepts ALL tool calls, including legitimate ones that may
  carry API keys, passwords, or connection strings as arguments (e.g. a
  database_query tool called with credentials in the DSN). Logging those
  verbatim would create a secondary credential-exposure risk. This module
  scrubs them before any persistence or transmission.

Control via environment variable:
  PHANTOM_SNARE_LOG_ARGS=false   — omit arguments entirely from logs/webhooks
  PHANTOM_SNARE_LOG_ARGS=true    — include arguments (scrubbed, default)
"""

import re
import json
import os
from typing import Any


# Whether to include (scrubbed) arguments at all. Default: yes, but scrubbed.
_LOG_ARGS = os.environ.get("PHANTOM_SNARE_LOG_ARGS", "true").lower() not in ("false", "0", "no")


# Sensitive field names whose values should be redacted.
# Matched in both JSON format ("key": "value") and key=value / key: value forms.
_SENSITIVE_KEYS = (
    r'api[_-]?key|apikey|api[_-]?token|access[_-]?token|auth[_-]?token|bearer'
    r'|password|passwd|pwd|secret|passphrase|private[_-]?key|client[_-]?secret'
    r'|refresh[_-]?token|id[_-]?token|session[_-]?token|x[_-]?auth[_-]?token'
)

# Patterns that identify sensitive key=value or header: value pairs.
# Each entry is (compiled_regex, replacement_string).
# IMPORTANT: JSON format ("key": "value") is listed first and uses non-greedy
# matching inside quotes to avoid over-redacting adjacent fields.
_SENSITIVE_PATTERNS: list[tuple[re.Pattern, str]] = [
    # JSON format: "sensitive_key": "some_value"
    (re.compile(
        r'("(?:' + _SENSITIVE_KEYS + r')")\s*:\s*"([^"\\]|\\.)*"',
        re.IGNORECASE,
    ), r'\1: "<REDACTED>"'),

    # JSON format: "sensitive_key": 'some_value' (single-quoted, rare but safe to handle)
    (re.compile(
        r"('(?:" + _SENSITIVE_KEYS + r")')\s*:\s*'([^'\\]|\\.)*'",
        re.IGNORECASE,
    ), r"\1: '<REDACTED>'"),

    # key=value form (query strings, env vars, config files)
    (re.compile(
        r'((?:' + _SENSITIVE_KEYS + r'))\s*=\s*\S+',
        re.IGNORECASE,
    ), r'\1=<REDACTED>'),

    # key: value form (YAML, plain-text headers)
    # (Only when not already handled by the JSON pattern above.)
    (re.compile(
        r'^((?:' + _SENSITIVE_KEYS + r'))\s*:\s*\S+',
        re.IGNORECASE | re.MULTILINE,
    ), r'\1: <REDACTED>'),

    # Database / broker connection strings that embed credentials
    (re.compile(
        r'(mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|amqps|mssql)'
        r'://[^:@\s"\']+:[^@\s"\']+@',
        re.IGNORECASE,
    ), r'\1://<REDACTED>:<REDACTED>@'),

    # AWS access key IDs
    (re.compile(r'AKIA[0-9A-Z]{16}'), '<AWS_KEY_REDACTED>'),

    # Authorization / X-API-Key HTTP header values (in plain-text form)
    (re.compile(
        r'(Authorization|X-API-Key|X-Auth-Token)\s*[=:]\s*\S+',
        re.IGNORECASE,
    ), r'\1: <REDACTED>'),

    # Private key / certificate PEM blocks
    (re.compile(
        r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
        re.DOTALL,
    ), '<PRIVATE_KEY_REDACTED>'),

    # Generic long hex/base64 strings inside JSON string literals (>= 32 chars)
    # — catches random-looking secrets but avoids redacting normal prose.
    # Applied LAST so earlier, more specific patterns take priority.
    (re.compile(r'(?<=["\'])([A-Za-z0-9+/=_-]{32,})(?=["\'])'), '<SECRET_REDACTED>'),
]


def scrub_arguments(args: Any) -> Any:
    """
    Return a scrubbed copy of tool arguments with sensitive values redacted.

    If PHANTOM_SNARE_LOG_ARGS=false, returns the sentinel string
    '<arguments hidden by PHANTOM_SNARE_LOG_ARGS>' instead.

    The input may be a dict, list, string, or None.
    The output type matches the input type where possible.
    """
    if not _LOG_ARGS:
        return "<arguments hidden by PHANTOM_SNARE_LOG_ARGS>"

    if args is None:
        return args

    # Serialise to JSON, apply regex passes, deserialise back.
    # This handles nested dicts/lists uniformly without walking them manually.
    is_str = isinstance(args, str)
    try:
        args_str = args if is_str else json.dumps(args, ensure_ascii=False)
    except (TypeError, ValueError):
        # Not JSON-serialisable — convert to repr string and scrub that
        args_str = repr(args)
        is_str = True

    for pattern, replacement in _SENSITIVE_PATTERNS:
        args_str = pattern.sub(replacement, args_str)

    if is_str:
        return args_str

    try:
        return json.loads(args_str)
    except (json.JSONDecodeError, ValueError):
        # Regex replacement broke the JSON (e.g. inside a string value) —
        # return the scrubbed string rather than the raw original
        return args_str


def scrub_preview(args: Any, max_chars: int = 300) -> str:
    """
    Return a scrubbed, truncated JSON preview of arguments for webhook messages.
    """
    scrubbed = scrub_arguments(args)
    if isinstance(scrubbed, str):
        preview = scrubbed
    else:
        try:
            preview = json.dumps(scrubbed)
        except (TypeError, ValueError):
            preview = repr(scrubbed)
    return preview[:max_chars]
