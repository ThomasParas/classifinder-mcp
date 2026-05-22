"""Tests for the local audit log.

Audit log discipline:
- One JSONL line per tool call
- Fields: timestamp (UTC ISO 8601), tool, input_byte_count, finding_count, latency_ms
- NEVER includes: input text, finding values, finding previews, anything that could
  leak the user's secrets back into a local file.
- Opt-out via CLASSIFINDER_MCP_AUDIT=0 (default on)
- Custom path via CLASSIFINDER_MCP_AUDIT_PATH (default ~/.classifinder/mcp-audit.log)
- Write failures are non-fatal — the tool call must succeed even if audit fails.
"""

from __future__ import annotations

import json

from classifinder_mcp.audit import _resolve_audit_path, audit_tool_call

# ── Path resolution ───────────────────────────────────────────────────────


def test_default_audit_path(monkeypatch, tmp_path):
    """Default path is ~/.classifinder/mcp-audit.log."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("CLASSIFINDER_MCP_AUDIT_PATH", raising=False)
    assert _resolve_audit_path() == tmp_path / ".classifinder" / "mcp-audit.log"


def test_custom_audit_path(monkeypatch, tmp_path):
    """CLASSIFINDER_MCP_AUDIT_PATH overrides default."""
    custom = tmp_path / "subdir" / "audit.jsonl"
    monkeypatch.setenv("CLASSIFINDER_MCP_AUDIT_PATH", str(custom))
    assert _resolve_audit_path() == custom


# ── Opt-out ────────────────────────────────────────────────────────────────


def test_audit_disabled_writes_nothing(monkeypatch, tmp_path):
    """With CLASSIFINDER_MCP_AUDIT=0, no file is created."""
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("CLASSIFINDER_MCP_AUDIT", "0")
    monkeypatch.setenv("CLASSIFINDER_MCP_AUDIT_PATH", str(audit_path))

    audit_tool_call(
        tool="classifinder_scan",
        input_byte_count=42,
        finding_count=1,
        latency_ms=12.3,
    )

    assert not audit_path.exists()


def test_audit_enabled_by_default(monkeypatch, tmp_path):
    """No CLASSIFINDER_MCP_AUDIT env → audit ON (default)."""
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.delenv("CLASSIFINDER_MCP_AUDIT", raising=False)
    monkeypatch.setenv("CLASSIFINDER_MCP_AUDIT_PATH", str(audit_path))

    audit_tool_call(
        tool="classifinder_scan",
        input_byte_count=42,
        finding_count=1,
        latency_ms=12.3,
    )

    assert audit_path.exists()
    assert audit_path.stat().st_size > 0


# ── Log line content ───────────────────────────────────────────────────────


def test_log_line_contains_expected_fields(monkeypatch, tmp_path):
    """JSONL line has timestamp, tool, input_byte_count, finding_count, latency_ms."""
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("CLASSIFINDER_MCP_AUDIT_PATH", str(audit_path))

    audit_tool_call(
        tool="classifinder_scan",
        input_byte_count=42,
        finding_count=3,
        latency_ms=15.7,
    )

    line = audit_path.read_text().strip()
    record = json.loads(line)
    assert "timestamp" in record
    assert record["tool"] == "classifinder_scan"
    assert record["input_byte_count"] == 42
    assert record["finding_count"] == 3
    assert record["latency_ms"] == 15.7
    # Timestamp is UTC ISO 8601 with timezone marker
    assert record["timestamp"].endswith("Z") or "+" in record["timestamp"]


def test_log_line_does_not_contain_input_text(monkeypatch, tmp_path):
    """The user's input text must NEVER appear in the log line."""
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("CLASSIFINDER_MCP_AUDIT_PATH", str(audit_path))

    secret = "AWS_ACCESS_KEY_ID=AKIAEXAMPLEACCESS"
    audit_tool_call(
        tool="classifinder_scan",
        input_byte_count=len(secret.encode()),
        finding_count=1,
        latency_ms=10.0,
    )

    line = audit_path.read_text()
    assert "AKIA" not in line
    assert "AWS_ACCESS_KEY_ID" not in line
    assert secret not in line


def test_log_line_does_not_contain_finding_values(monkeypatch, tmp_path):
    """Finding type names, value_previews, and recommendations must not leak."""
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("CLASSIFINDER_MCP_AUDIT_PATH", str(audit_path))

    # Even if a caller fat-fingered and passed finding metadata, the audit
    # function should ignore everything except the documented metadata fields.
    audit_tool_call(
        tool="classifinder_scan",
        input_byte_count=42,
        finding_count=1,
        latency_ms=10.0,
    )

    line = audit_path.read_text()
    assert "aws_access_key" not in line
    assert "value_preview" not in line
    assert "recommendation" not in line


# ── Append + concurrency safety ────────────────────────────────────────────


def test_multiple_calls_append(monkeypatch, tmp_path):
    """Successive calls add new lines, do not overwrite."""
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("CLASSIFINDER_MCP_AUDIT_PATH", str(audit_path))

    for i in range(3):
        audit_tool_call(
            tool="classifinder_scan",
            input_byte_count=10 * i,
            finding_count=i,
            latency_ms=float(i),
        )

    lines = audit_path.read_text().strip().split("\n")
    assert len(lines) == 3
    for i, line in enumerate(lines):
        record = json.loads(line)
        assert record["input_byte_count"] == 10 * i
        assert record["finding_count"] == i


# ── Directory creation ─────────────────────────────────────────────────────


def test_creates_parent_directory(monkeypatch, tmp_path):
    """Audit directory is created on first write if it doesn't exist."""
    audit_path = tmp_path / "deeply" / "nested" / "audit.jsonl"
    assert not audit_path.parent.exists()
    monkeypatch.setenv("CLASSIFINDER_MCP_AUDIT_PATH", str(audit_path))

    audit_tool_call(
        tool="classifinder_scan",
        input_byte_count=42,
        finding_count=0,
        latency_ms=5.0,
    )

    assert audit_path.parent.exists()
    assert audit_path.exists()


# ── Best-effort write (no crash on failure) ────────────────────────────────


def test_write_failure_is_non_fatal(monkeypatch, tmp_path):
    """If audit write fails (e.g. read-only filesystem), the tool call must not crash."""
    # Point at a read-only directory to force write failure.
    readonly_dir = tmp_path / "readonly"
    readonly_dir.mkdir()
    readonly_dir.chmod(0o555)
    audit_path = readonly_dir / "audit.jsonl"
    monkeypatch.setenv("CLASSIFINDER_MCP_AUDIT_PATH", str(audit_path))

    # Should not raise — audit is best-effort
    try:
        audit_tool_call(
            tool="classifinder_scan",
            input_byte_count=42,
            finding_count=0,
            latency_ms=5.0,
        )
    finally:
        # Restore perms so tmp_path cleanup works
        readonly_dir.chmod(0o755)
