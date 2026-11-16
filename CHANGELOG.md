# Changelog

## [0.2.0] - 2026-11-15
### Added
- Dedicated MCP configuration auditor (`llm-keyguard audit-mcp`) reporting JSON key paths for hardcoded server credentials.
- OASIS SARIF v2.1.0 output formatter (`--format sarif`) for GitHub Code Scanning.
- Expanded provider rule catalog to 20 signatures covering OpenAI (`sk-proj-`, `sk-svcacct-`, `sk-admin-`), Anthropic, Gemini, Groq, OpenRouter, HuggingFace, Replicate, Perplexity, Fireworks, Tavily, Pinecone, LangSmith, ElevenLabs, Supabase, GitHub, AWS, Stripe, Slack, and PEM keys.
- `llm-keyguard env-example` generator and `llm-keyguard init` `.gitignore` + `pre-commit` installer.
