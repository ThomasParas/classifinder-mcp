# ClassiFinder MCP Server

An [MCP](https://modelcontextprotocol.io) server that gives AI agents the ability to scan text for leaked secrets and redact them before they reach an LLM.

## Installation

```bash
pip install classifinder-mcp
```

## Setup

Get a free API key at [classifinder.ai](https://classifinder.ai), then add to your agent config:

### Claude Code

```json
{
  "mcpServers": {
    "classifinder": {
      "command": "classifinder-mcp",
      "env": {
        "CLASSIFINDER_API_KEY": "ss_live_your_key_here"
      }
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "classifinder": {
      "command": "classifinder-mcp",
      "env": {
        "CLASSIFINDER_API_KEY": "ss_live_your_key_here"
      }
    }
  }
}
```

## Tools

### `classifinder_scan`

Scan text for leaked secrets and credentials. Returns findings with type, severity, confidence, and remediation guidance.

```
Agent: "Check this config for secrets"
→ classifinder_scan(text="AWS_ACCESS_KEY_ID=AKIAJGKJHSKLDJFH3284")
→ Found 1 secret: aws_access_key (critical, confidence 0.95)
```

### `classifinder_redact`

Replace all detected secrets with safe placeholders. Returns clean text safe to forward to any LLM.

```
Agent: "Clean this before sending to the model"
→ classifinder_redact(text="key=sk_live_EXAMPLE_KEY_HERE")
→ "key=[STRIPE_LIVE_SECRET_KEY_REDACTED]"
```

## What It Detects

106 secret types including AWS keys, Stripe keys, GitHub tokens, OpenAI/Anthropic/Cohere API keys, database connection strings, private keys, credit card numbers, and more.

## See Also

For CLI scanning instead of MCP, see [cfsniff](https://github.com/classifinder/cfsniff) — a command-line tool that scans files, shell history, and configs for secrets (`pipx install cfsniff`).

## Disclaimer

ClassiFinder is a detection aid, not a guarantee. No scanner catches 100% of secrets in 100% of formats. See our [Terms of Service](https://classifinder.ai) for full details.

## License

MIT
