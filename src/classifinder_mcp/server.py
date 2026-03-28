"""
ClassiFinder MCP Server

Exposes ClassiFinder scan and redact as MCP tools for AI agents.
Connects via stdio transport. Requires CLASSIFINDER_API_KEY env var.

Usage:
    classifinder-mcp                     # run as stdio server
    python -m classifinder_mcp.server    # alternative

Agent config (Claude Code / Cursor):
    {
      "mcpServers": {
        "classifinder": {
          "command": "classifinder-mcp",
          "env": {"CLASSIFINDER_API_KEY": "ss_live_..."}
        }
      }
    }
"""

import json
import os

from mcp.server.fastmcp import FastMCP

# ── Server setup ─────────────────────────────────────────────────────────

mcp = FastMCP(
    "ClassiFinder",
    instructions="Scan text for leaked secrets and credentials. Redact secrets before sending to LLMs.",
)

_client = None


def _get_client():
    """Lazy-initialize the ClassiFinder client."""
    global _client
    if _client is not None:
        return _client

    api_key = os.environ.get("CLASSIFINDER_API_KEY")
    if not api_key:
        raise RuntimeError(
            "CLASSIFINDER_API_KEY environment variable is not set. "
            "Get a free key at https://classifinder.ai"
        )

    from classifinder import ClassiFinder
    _client = ClassiFinder(api_key=api_key)
    return _client


# ── Tools ────────────────────────────────────────────────────────────────

@mcp.tool()
def classifinder_scan(text: str, min_confidence: float = 0.5) -> str:
    """Scan text for leaked secrets and credentials.

    Returns structured findings with type, severity, confidence, and
    remediation guidance. Use this to check if text contains API keys,
    passwords, tokens, or other sensitive credentials.

    Args:
        text: The text to scan for secrets.
        min_confidence: Minimum confidence threshold (0.0-1.0). Default 0.5.
    """
    try:
        client = _get_client()
        result = client.scan(text=text, min_confidence=min_confidence)

        if result.findings_count == 0:
            return "No secrets detected."

        findings = []
        for f in result.findings:
            findings.append({
                "type": f.type,
                "type_name": f.type_name,
                "severity": f.severity,
                "confidence": f.confidence,
                "value_preview": f.value_preview,
                "recommendation": f.recommendation,
            })

        return json.dumps({
            "findings_count": result.findings_count,
            "summary": {
                "critical": result.summary.critical,
                "high": result.summary.high,
                "medium": result.summary.medium,
                "low": result.summary.low,
            },
            "findings": findings,
        }, indent=2)

    except RuntimeError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"ClassiFinder API error: {e}"


@mcp.tool()
def classifinder_redact(text: str, redaction_style: str = "label") -> str:
    """Scan text and replace all detected secrets with safe placeholders.

    Returns clean text safe to forward to any LLM or logging system.
    Use this before sending user input to a model.

    Args:
        text: The text to redact.
        redaction_style: How to replace secrets. Options:
            "label" - [AWS_ACCESS_KEY_REDACTED] (default)
            "mask"  - AKIA**************
            "hash"  - [REDACTED:sha256:a1b2c3d4]
    """
    try:
        client = _get_client()
        result = client.redact(
            text=text,
            redaction_style=redaction_style,
        )

        if result.findings_count == 0:
            return text  # No secrets found, return original

        return json.dumps({
            "redacted_text": result.redacted_text,
            "findings_count": result.findings_count,
            "summary": {
                "critical": result.summary.critical,
                "high": result.summary.high,
                "medium": result.summary.medium,
                "low": result.summary.low,
            },
        }, indent=2)

    except RuntimeError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"ClassiFinder API error: {e}"


# ── Entry point ──────────────────────────────────────────────────────────

def main():
    """Run the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
