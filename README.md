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

**178 detection patterns:**

- **164 secret types** across 10 categories: cloud/infra keys (AWS, GCP, Azure, Vercel including the 2024+ prefixed taxonomy vcp_/vci_/vca_/vcr_/vck_, Fly.io, Doppler, HashiCorp Vault, Cloudflare, Dropbox, JFrog/Artifactory and more); payment (Stripe, PayPal, Shopify with 4 token types, credit cards Luhn-validated, Square); VCS (GitHub, GitLab with 10 token types covering deploy/feed/runner/SCIM/k8s-agent/OAuth/feature-flag, Bitbucket); comms/SaaS (Slack including config/session/legacy variants, Twilio, SendGrid, Mailgun, Datadog, Sentry, PagerDuty, Notion, Linear and more); database connection strings (PostgreSQL/MySQL/MongoDB/Redis/Supabase); generic SSH/PEM private keys and JWTs; AI/LLM provider keys (OpenAI, Anthropic user + admin, Cohere, xAI, Mistral, DeepSeek, HuggingFace user + organization, Replicate, Groq, ElevenLabs, AssemblyAI, Deepgram, LangFuse, AWS Bedrock long + short-lived, Vercel AI Gateway, Weights & Biases); DevOps/CI-CD/observability (Databricks, Dynatrace, LaunchDarkly, Harness, Octopus Deploy, Fastly, Gitea, TravisCI, Prefect, Infracost, Sumo Logic, Snyk, Sonar, Sourcegraph); data/analytics (ClickHouse, PlanetScale, PostHog, Postman, Algolia, Contentful); and enterprise identity (Atlassian, 1Password, HubSpot, Mapbox, MaxMind, Zendesk).
- **14 prompt-injection markers** for LLM input scanning — **4 phase-1 high-precision** (chat-template role-hijack tokens like `<|im_start|>` and `[INST]`, tool-call tag injection, known jailbreak personas like DAN/AIM, Unicode bidirectional override / Trojan Source) + **6 phase-2 medium-precision** (zero-width Unicode smuggling, fake "Assistant:" turns, system-prompt extraction, instruction override like "ignore previous instructions", persona override (context-gated), encoded-payload markers) + **4 phase-3 SAFE-MCP-derived** markers cross-referenced to the SAFE-MCP technique catalog. Catches 20.6% of in-the-wild jailbreaks (validated against the `verazuo/jailbreak_llms` corpus). Severity caps at `high` — these are attack markers, not credentials.

One scan returns both secret findings and injection markers — no second vendor, no separate pipeline.

## See Also

For CLI scanning instead of MCP, see [cfsniff](https://github.com/ClassiFinder/cfsniff) — a command-line tool that scans files, shell history, and configs for secrets (`pipx install cfsniff`).

## Disclaimer

ClassiFinder is a detection aid, not a guarantee. No scanner catches 100% of secrets in 100% of formats. See our [Terms of Service](https://classifinder.ai) for full details.

## License

MIT
