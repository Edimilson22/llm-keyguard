# llm-keyguard

**Zero-dependency secret scanner, MCP configuration auditor, and `<35ms` Git pre-commit guard for LLM & AI API keys.**

Modern AI engineering introduces new credential leak vectors beyond traditional web apps: developers frequently commit `.mcp.json`, `.cursor/mcp.json`, Jupyter notebooks, and agent configuration files containing live keys for OpenAI, Anthropic, Gemini, Groq, OpenRouter, Pinecone, LangSmith, HuggingFace, and ElevenLabs.

`llm-keyguard` is a pure-Python, zero-dependency CLI and library designed to stop AI credential leaks before they enter Git history—without requiring external Go binaries or Docker containers.

---

## Features

- **20+ AI, Vector DB & Cloud Signatures + Shannon Entropy Filtering:** Detects OpenAI (`sk-proj-`, `sk-svcacct-`, `sk-admin-`), Anthropic (`sk-ant-`), Google Gemini (`AIzaSy`), Groq (`gsk_`), OpenRouter (`sk-or-v1-`), HuggingFace (`hf_`), Replicate (`r8_`), Perplexity (`pplx-`), Fireworks (`fw_`), Tavily (`tvly-`), Pinecone (`pcsk_`), LangSmith (`lsv2_`), ElevenLabs, Supabase, GitHub PATs, AWS IAM, Stripe Live, Slack, and PEM private keys while ignoring low-entropy placeholders.
- **Dedicated MCP Config Auditor (`audit-mcp`):** Parses `mcp.json`, `.mcp.json`, `.cursor/mcp.json`, and `claude_desktop_config.json` to pinpoint exact JSON paths (e.g. `mcpServers.search.env.OPENAI_API_KEY`) containing literal credentials instead of environment references.
- **One-Command Repository Hardening (`init`):** Automatically hardens `.gitignore` (blocking `.env` and key files while allowing `.env.example`) and installs a fast native Git `pre-commit` hook.
- **Safe `.env.example` Generator (`env-example`):** Generates sanitized `.env.example` templates from local `.env` files without exposing real credentials.
- **OASIS SARIF v2.1.0 Export (`--format sarif`):** Integrates directly with GitHub Code Scanning and CI pipelines.

---

## Quickstart

```bash
pip install llm-keyguard

# 1. Harden .gitignore and install the Git pre-commit guard
llm-keyguard init

# 2. Scan your project directory (including MCP configs)
llm-keyguard scan .

# 3. Audit MCP configuration files specifically
llm-keyguard audit-mcp .

# 4. Generate a safe .env.example from your local .env
llm-keyguard env-example --source .env --output .env.example
```

---

## Using with `pre-commit`

Add `llm-keyguard` to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Edimilson22/llm-keyguard
    rev: v0.2.0
    hooks:
      - id: llm-keyguard
```

---

## GitHub Actions & Code Scanning (SARIF)

```yaml
name: AI Credential Scan
on: [push, pull_request]

jobs:
  keyguard:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install llm-keyguard
      - run: llm-keyguard scan . --format sarif > results.sarif || true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Python API

```python
from pathlib import Path
from llm_keyguard import scan_path, audit_mcp_configs, build_sarif_report

findings = scan_path(Path("."))
for item in findings:
    print(f"[{item.rule_id}] {item.file}:{item.line} -> {item.provider} ({item.masked})")

mcp_issues = audit_mcp_configs(Path("."))
sarif_payload = build_sarif_report(findings)
```

---

## Inline Suppression

For intentional synthetic test fixtures, append `# keyguard: ignore` (or `# pragma: allowlist secret`) to the line:

```python
TEST_FIXTURE = "sk-proj-..."  # keyguard: ignore
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
