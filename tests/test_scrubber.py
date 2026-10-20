"""
Tests for argument scrubbing (scrubber.py).
Verifies that credentials are redacted before reaching logs or webhooks.
"""
import sys
import os
import json
sys.path.insert(0, "../src")

from phantom_snare.scrubber import scrub_arguments, scrub_preview


# ── Basic scrubbing ──────────────────────────────────────────────────────────

def test_api_key_redacted():
    args = {"api_key": "sk-abc123def456", "query": "hello"}
    result = scrub_arguments(args)
    dumped = json.dumps(result)
    assert "sk-abc123def456" not in dumped, "API key leaked"
    assert "REDACTED" in dumped


def test_password_redacted():
    args = {"password": "hunter2", "username": "alice"}
    result = scrub_arguments(args)
    dumped = json.dumps(result)
    assert "hunter2" not in dumped, "Password leaked"
    assert "REDACTED" in dumped


def test_connection_string_redacted():
    args = {"dsn": "postgres://user:s3cr3t@db.example.com/mydb"}
    result = scrub_arguments(args)
    dumped = json.dumps(result)
    assert "s3cr3t" not in dumped, "DB password leaked in connection string"
    assert "REDACTED" in dumped


def test_aws_key_redacted():
    args = {"key_id": "AKIAIOSFODNN7EXAMPLE"}
    result = scrub_arguments(args)
    dumped = json.dumps(result)
    assert "AKIAIOSFODNN7EXAMPLE" not in dumped, "AWS key leaked"
    assert "AWS_KEY_REDACTED" in dumped


def test_auth_header_redacted():
    args = {"headers": "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"}
    result = scrub_arguments(args)
    assert "eyJhbGciOiJIUzI1NiJ9" not in result, "Bearer token leaked"


def test_long_secret_redacted():
    # A 40-char hex string in a JSON string literal should be redacted
    secret = "a" * 40
    args = {"token": secret}
    result = scrub_arguments(args)
    dumped = json.dumps(result)
    assert secret not in dumped, "Long hex secret leaked"


def test_none_passthrough():
    assert scrub_arguments(None) is None


def test_innocent_args_unchanged():
    args = {"query": "SELECT * FROM users", "limit": 10}
    result = scrub_arguments(args)
    assert result["query"] == "SELECT * FROM users"
    assert result["limit"] == 10


def test_string_input():
    s = "password=hunter2"
    result = scrub_arguments(s)
    assert "hunter2" not in result
    assert "REDACTED" in result


# ── Preview helper ──────────────────────────────────────────────────────────

def test_preview_truncates():
    args = {"data": "x" * 500}
    preview = scrub_preview(args, max_chars=100)
    assert len(preview) <= 100


def test_preview_scrubs():
    args = {"api_key": "sk-verysecretkey1234567890"}
    preview = scrub_preview(args)
    assert "sk-verysecretkey1234567890" not in preview


# ── PHANTOM_SNARE_LOG_ARGS=false ────────────────────────────────────────────

def test_log_args_false_hides_everything(monkeypatch):
    """When LOG_ARGS is false, arguments must be fully suppressed."""
    import phantom_snare.scrubber as sc
    original = sc._LOG_ARGS
    try:
        sc._LOG_ARGS = False
        result = scrub_arguments({"api_key": "secret", "cmd": "ls"})
        assert "secret" not in str(result)
        assert "hidden" in str(result).lower() or "PHANTOM_SNARE_LOG_ARGS" in str(result)
    finally:
        sc._LOG_ARGS = original


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)
             and k != "test_log_args_false_hides_everything"]  # skip monkeypatch test in plain run
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    if failed:
        sys.exit(1)
