"""Tests for the ClassiFinder MCP server."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from classifinder_mcp.server import (
    _get_client,
    classifinder_redact,
    classifinder_scan,
    main,
    mcp,
)

# ── _get_client() ───────────────────────────────────────────────────────


def test_get_client_raises_without_api_key(monkeypatch):
    """Missing CLASSIFINDER_API_KEY should raise RuntimeError."""
    import classifinder_mcp.server as server_mod

    server_mod._client = None
    monkeypatch.delenv("CLASSIFINDER_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="CLASSIFINDER_API_KEY"):
        _get_client()


def test_get_client_returns_instance(monkeypatch):
    """With API key set, should return a ClassiFinder client."""
    import classifinder_mcp.server as server_mod

    server_mod._client = None
    monkeypatch.setenv("CLASSIFINDER_API_KEY", "ss_test_abc123")
    mock_instance = MagicMock()

    import classifinder

    with (
        patch.dict("sys.modules", {"classifinder": classifinder}),
        patch.object(classifinder, "ClassiFinder", return_value=mock_instance, create=True),
    ):
        _get_client()
    server_mod._client = None  # reset


def test_get_client_caches_instance(monkeypatch):
    """Repeated calls should return the same client object."""
    import classifinder_mcp.server as server_mod

    sentinel = MagicMock()
    server_mod._client = sentinel
    assert _get_client() is sentinel
    server_mod._client = None  # reset


# ── classifinder_scan() ─────────────────────────────────────────────────


def test_scan_no_secrets_returns_message():
    mock_result = MagicMock()
    mock_result.findings_count = 0
    mock_client = MagicMock()
    mock_client.scan.return_value = mock_result

    with patch("classifinder_mcp.server._get_client", return_value=mock_client):
        result = classifinder_scan("Hello world")

    assert result == "No secrets detected."


def test_scan_with_findings_returns_json():
    finding = MagicMock()
    finding.type = "aws_access_key"
    finding.type_name = "AWS Access Key ID"
    finding.severity = "critical"
    finding.confidence = 0.95
    finding.value_preview = "AKIA****7EPN"
    finding.recommendation = "Rotate the key."

    mock_result = MagicMock()
    mock_result.findings_count = 1
    mock_result.findings = [finding]
    mock_result.summary.critical = 1
    mock_result.summary.high = 0
    mock_result.summary.medium = 0
    mock_result.summary.low = 0

    mock_client = MagicMock()
    mock_client.scan.return_value = mock_result

    with patch("classifinder_mcp.server._get_client", return_value=mock_client):
        result = classifinder_scan("AWS_KEY=AKIAZ3MHQWRSDHOF7EPN")

    data = json.loads(result)
    assert data["findings_count"] == 1
    assert data["findings"][0]["type"] == "aws_access_key"
    assert data["summary"]["critical"] == 1


def test_scan_runtime_error_returns_error_string():
    with patch("classifinder_mcp.server._get_client", side_effect=RuntimeError("no key")):
        result = classifinder_scan("test")
    assert "Error:" in result
    assert "no key" in result


def test_scan_classifinder_error_returns_error_string():
    from classifinder import ClassiFinderError

    mock_client = MagicMock()
    mock_client.scan.side_effect = ClassiFinderError("rate limited", status_code=429)

    with patch("classifinder_mcp.server._get_client", return_value=mock_client):
        result = classifinder_scan("test")
    assert "ClassiFinder API error" in result


# ── classifinder_redact() ───────────────────────────────────────────────


def test_redact_no_secrets_returns_original_text():
    mock_result = MagicMock()
    mock_result.findings_count = 0

    mock_client = MagicMock()
    mock_client.redact.return_value = mock_result

    with patch("classifinder_mcp.server._get_client", return_value=mock_client):
        result = classifinder_redact("Hello world")

    assert result == "Hello world"


def test_redact_with_findings_returns_json():
    mock_result = MagicMock()
    mock_result.findings_count = 1
    mock_result.redacted_text = "key=[AWS_ACCESS_KEY_REDACTED]"
    mock_result.summary.critical = 1
    mock_result.summary.high = 0
    mock_result.summary.medium = 0
    mock_result.summary.low = 0

    mock_client = MagicMock()
    mock_client.redact.return_value = mock_result

    with patch("classifinder_mcp.server._get_client", return_value=mock_client):
        result = classifinder_redact("key=AKIAZ3MHQWRSDHOF7EPN")

    data = json.loads(result)
    assert data["findings_count"] == 1
    assert "[AWS_ACCESS_KEY_REDACTED]" in data["redacted_text"]


def test_redact_passes_style_to_client():
    mock_result = MagicMock()
    mock_result.findings_count = 0

    mock_client = MagicMock()
    mock_client.redact.return_value = mock_result

    with patch("classifinder_mcp.server._get_client", return_value=mock_client):
        classifinder_redact("test", redaction_style="mask")

    mock_client.redact.assert_called_once_with(text="test", redaction_style="mask")


# ── main() ──────────────────────────────────────────────────────────────


def test_main_calls_mcp_run():
    with patch.object(mcp, "run") as mock_run:
        main()
    mock_run.assert_called_once_with(transport="stdio")


# ── Audit integration ──────────────────────────────────────────────────────


def test_scan_writes_audit_line(monkeypatch, tmp_path):
    """A successful scan call writes one audit line with metadata."""
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("CLASSIFINDER_MCP_AUDIT_PATH", str(audit_path))
    monkeypatch.delenv("CLASSIFINDER_MCP_AUDIT", raising=False)

    mock_result = MagicMock()
    mock_result.findings_count = 2
    mock_result.findings = []
    mock_result.summary.critical = 0
    mock_result.summary.high = 0
    mock_result.summary.medium = 0
    mock_result.summary.low = 0
    mock_client = MagicMock()
    mock_client.scan.return_value = mock_result

    text = "API_KEY=sk_test_abc123"
    with patch("classifinder_mcp.server._get_client", return_value=mock_client):
        classifinder_scan(text)

    line = audit_path.read_text().strip()
    record = json.loads(line)
    assert record["tool"] == "classifinder_scan"
    assert record["input_byte_count"] == len(text.encode())
    assert record["finding_count"] == 2
    assert isinstance(record["latency_ms"], float)
    # Critical: no input text in the log
    assert "sk_test_abc123" not in audit_path.read_text()


def test_redact_writes_audit_line(monkeypatch, tmp_path):
    """A successful redact call writes one audit line."""
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("CLASSIFINDER_MCP_AUDIT_PATH", str(audit_path))
    monkeypatch.delenv("CLASSIFINDER_MCP_AUDIT", raising=False)

    mock_result = MagicMock()
    mock_result.findings_count = 1
    mock_result.redacted_text = "[REDACTED]"
    mock_result.summary.critical = 1
    mock_result.summary.high = 0
    mock_result.summary.medium = 0
    mock_result.summary.low = 0
    mock_client = MagicMock()
    mock_client.redact.return_value = mock_result

    text = "AWS_KEY=AKIAEXAMPLE"
    with patch("classifinder_mcp.server._get_client", return_value=mock_client):
        classifinder_redact(text)

    line = audit_path.read_text().strip()
    record = json.loads(line)
    assert record["tool"] == "classifinder_redact"
    assert record["input_byte_count"] == len(text.encode())
    assert record["finding_count"] == 1
    # Critical: redacted text + input text both absent from log
    log_content = audit_path.read_text()
    assert "AKIAEXAMPLE" not in log_content
    assert "REDACTED" not in log_content


def test_audit_disabled_skips_write(monkeypatch, tmp_path):
    """CLASSIFINDER_MCP_AUDIT=0 → no audit line on tool call."""
    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("CLASSIFINDER_MCP_AUDIT_PATH", str(audit_path))
    monkeypatch.setenv("CLASSIFINDER_MCP_AUDIT", "0")

    mock_result = MagicMock()
    mock_result.findings_count = 0
    mock_client = MagicMock()
    mock_client.scan.return_value = mock_result

    with patch("classifinder_mcp.server._get_client", return_value=mock_client):
        classifinder_scan("test")

    assert not audit_path.exists()


def test_audit_skipped_on_error_path(monkeypatch, tmp_path):
    """When the SDK raises, the tool returns an error string AND no audit
    line is written — we don't have meaningful metadata to log on the error path."""
    from classifinder import ClassiFinderError

    audit_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("CLASSIFINDER_MCP_AUDIT_PATH", str(audit_path))
    monkeypatch.delenv("CLASSIFINDER_MCP_AUDIT", raising=False)

    mock_client = MagicMock()
    mock_client.scan.side_effect = ClassiFinderError("rate limited", status_code=429)

    with patch("classifinder_mcp.server._get_client", return_value=mock_client):
        result = classifinder_scan("test")

    assert "ClassiFinder API error" in result
    assert not audit_path.exists()
