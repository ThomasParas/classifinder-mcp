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

## Hardening — Sandbox Profiles

The MCP server is intentionally minimal: ~180 lines, two read-only tools, a single egress destination (`api.classifinder.ai:443`), and the API key as the only secret in scope. That makes it cheap to run under a sandbox. Three documented profiles:

### Docker

```bash
docker run --rm -i \
  --read-only \
  --tmpfs /tmp \
  -v ~/.classifinder:/root/.classifinder \
  -e CLASSIFINDER_API_KEY \
  python:3.12-slim sh -c "pip install -q classifinder-mcp && classifinder-mcp"
```

- `--read-only` — container filesystem is read-only
- `--tmpfs /tmp` — writable scratch space for pip / Python
- `-v ~/.classifinder:/root/.classifinder` — only persistent mount, used for the audit log
- `-e CLASSIFINDER_API_KEY` — key passed via env, never written to disk
- `-i` — keeps stdin attached (MCP transport is stdio)

For a faster invocation in production, build a thin image with `classifinder-mcp` pre-installed.

### Firejail (Linux)

```bash
firejail \
  --noroot \
  --caps.drop=all \
  --seccomp \
  --private-tmp \
  --whitelist=~/.classifinder \
  --read-only=~ \
  --read-write=~/.classifinder \
  classifinder-mcp
```

- Drops all capabilities + applies a default seccomp filter
- Filesystem: home is read-only, only `~/.classifinder/` writable
- Process runs without root privilege escalation
- Network egress remains open (required for `api.classifinder.ai`) — pair with host-level egress filtering (`ufw`, `iptables`, or `nftables`) if you want network restriction

### Bubblewrap (Linux)

```bash
bwrap \
  --ro-bind / / \
  --bind ~/.classifinder ~/.classifinder \
  --proc /proc --dev /dev --tmpfs /tmp \
  --unshare-pid --unshare-uts --new-session --die-with-parent \
  --setenv CLASSIFINDER_API_KEY "$CLASSIFINDER_API_KEY" \
  classifinder-mcp
```

- Read-only bind mount of `/`; writable bind only for `~/.classifinder/`
- Fresh PID + UTS namespaces; new session
- `--die-with-parent` ensures the sandbox tears down if the host process exits
- API key passed via setenv, no file mount needed

### Verification

These profiles are documented starting points. None are exercised in this repo's CI — they're correctness-by-construction (read-only bind mounts, dropped caps, single-purpose tmpfs) rather than test-validated. If you run a sandbox in production and want me to roll a verified profile into a future release, open an issue with the exact invocation you're using.

## Audit Log

The MCP server appends one JSONL line per tool call to a local audit file. Metadata only — the audit log **never** contains your input text or any detected secret values.

**Default path:** `~/.classifinder/mcp-audit.log`

**Fields per line:**

```json
{
  "timestamp": "2026-05-22T15:30:42.123456Z",
  "tool": "classifinder_scan",
  "input_byte_count": 142,
  "finding_count": 1,
  "latency_ms": 87.4
}
```

**Configuration (env vars):**

| Variable | Default | Purpose |
|---|---|---|
| `CLASSIFINDER_MCP_AUDIT` | `1` (on) | Set to `0` to disable logging entirely |
| `CLASSIFINDER_MCP_AUDIT_PATH` | `~/.classifinder/mcp-audit.log` | Override the log path |

The audit log is observability for your own use — useful for compliance (proving the MCP server ran), debugging (correlating latency spikes), and forensic review (which tool ran when). Write failures are silent; the tool call always succeeds even if the audit cannot be written.

## Verifying a Release

Every published release is signed twice:

1. **PyPI attestations (PEP 740)** — minted by PyPI from this repo's OIDC identity during publish. Verified automatically by `pip` when installing from PyPI; you don't need to do anything.
2. **Sigstore bundles** — published as GitHub Release assets (`*.sigstore.json` next to the sdist + wheel). Verify with `sigstore-python`:

```bash
pip install sigstore
gh release download v0.1.4 --repo ClassiFinder/classifinder-mcp \
  --pattern '*.whl' --pattern '*.sigstore.json'

sigstore verify identity \
  --bundle classifinder_mcp-0.1.4-py3-none-any.whl.sigstore.json \
  --cert-identity 'https://github.com/ClassiFinder/classifinder-mcp/.github/workflows/release.yml@refs/tags/v0.1.4' \
  --cert-oidc-issuer 'https://token.actions.githubusercontent.com' \
  classifinder_mcp-0.1.4-py3-none-any.whl
```

The signing identity binds the artifact to this repo's `release.yml` workflow at a specific tag — an attacker can't forge a valid bundle without compromising GitHub's OIDC token issuance.

## See Also

For CLI scanning instead of MCP, see [cfsniff](https://github.com/ClassiFinder/cfsniff) — a command-line tool that scans files, shell history, and configs for secrets (`pipx install cfsniff`).

## Disclaimer

ClassiFinder is a detection aid, not a guarantee. No scanner catches 100% of secrets in 100% of formats. See our [Terms of Service](https://classifinder.ai) for full details.

## License

MIT
