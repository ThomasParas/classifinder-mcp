# Contributing to ClassiFinder MCP Server

Thanks for your interest in contributing! This is the [MCP](https://modelcontextprotocol.io) server that gives AI agents access to ClassiFinder's secret scanning tools.

## Getting Started

```bash
git clone https://github.com/classifinder/classifinder-mcp.git
cd classifinder-mcp
pip install -e .
```

Requires Python 3.10+. You'll need a ClassiFinder API key (free at [classifinder.ai](https://classifinder.ai)) to test.

## Ways to Contribute

### Bug Reports

[Open an issue](https://github.com/classifinder/classifinder-mcp/issues) with:

- MCP server version (`pip show classifinder-mcp`)
- Which AI agent you're using (Claude Code, Cursor, etc.)
- What happened vs what you expected

### Feature Requests

Ideas for new MCP tools, better tool descriptions, or improved agent ergonomics are welcome as issues.

### Code Contributions

Good first contributions:

- Improving tool descriptions (these directly affect how well agents use the tools)
- Better error handling and error messages
- Adding tests
- Documentation improvements

## Project Structure

```
src/classifinder_mcp/
└── server.py    # MCP server entry point, tool definitions
```

The server is thin — it wraps the `classifinder` Python SDK to expose `classifinder_scan` and `classifinder_redact` as MCP tools.

## Code Style

- Python 3.10+ compatible
- Type hints on all functions
- PEP 8, 100-character line limit

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Test with at least one MCP-compatible agent (Claude Code, Cursor, etc.)
4. Open a PR with a clear description of what changed and why

## Security

If you discover a security vulnerability, please email security@classifinder.ai rather than opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
