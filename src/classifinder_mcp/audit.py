"""Local audit log for ClassiFinder MCP tool calls.

Discipline (mirrors the API server's logging rule):
  - One JSONL line per tool call.
  - Metadata only: timestamp, tool name, input byte count, finding count, latency.
  - NEVER write the user's input text, finding values, value_previews, or any
    other content that could leak secrets back into a local file.

Configuration:
  - CLASSIFINDER_MCP_AUDIT=0 disables logging entirely (default ON).
  - CLASSIFINDER_MCP_AUDIT_PATH overrides the log path
    (default: ~/.classifinder/mcp-audit.log).

Failure handling:
  - Write failures (read-only FS, permission errors) are swallowed silently.
    The audit log is observability, not a contract — losing a line must
    never break a tool call.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

_DEFAULT_AUDIT_DIR = ".classifinder"
_DEFAULT_AUDIT_FILE = "mcp-audit.log"


def _resolve_audit_path() -> Path:
    """Return the audit log path, env-override or default."""
    override = os.environ.get("CLASSIFINDER_MCP_AUDIT_PATH")
    if override:
        return Path(override)
    home = Path(os.environ.get("HOME", str(Path.home())))
    return home / _DEFAULT_AUDIT_DIR / _DEFAULT_AUDIT_FILE


def _audit_enabled() -> bool:
    """Audit is ON by default; disabled by CLASSIFINDER_MCP_AUDIT=0."""
    return os.environ.get("CLASSIFINDER_MCP_AUDIT", "1") != "0"


def audit_tool_call(
    *,
    tool: str,
    input_byte_count: int,
    finding_count: int,
    latency_ms: float,
) -> None:
    """Append one JSONL audit line for a tool invocation.

    All parameters are keyword-only and limited to metadata — no input text
    or finding values are accepted. Best-effort: any I/O error is silenced.
    """
    if not _audit_enabled():
        return

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tool": tool,
        "input_byte_count": int(input_byte_count),
        "finding_count": int(finding_count),
        "latency_ms": round(float(latency_ms), 3),
    }

    try:
        path = _resolve_audit_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        # Best-effort: never fail a tool call because of audit write failure.
        return
