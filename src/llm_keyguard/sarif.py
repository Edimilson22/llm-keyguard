"""OASIS SARIF v2.1.0 report builder for GitHub Code Scanning integration."""

from __future__ import annotations

from typing import Any, Dict, Sequence

from .scanner import Finding
from .signatures import RULES


def build_sarif_report(findings: Sequence[Finding], version: str = "0.2.0") -> Dict[str, Any]:
    """Serialize findings into an OASIS SARIF v2.1.0 JSON-compatible dictionary."""
    rule_catalog = [
        {
            "id": r.rule_id,
            "name": r.provider,
            "shortDescription": {"text": r.provider},
            "help": {"text": r.remediation},
            "defaultConfiguration": {"level": r.severity},
        }
        for r in RULES
    ] + [
        {
            "id": "LLMKG000",
            "name": "Staged .env File",
            "shortDescription": {"text": "Live .env file staged for Git commit"},
            "help": {"text": "Unstage .env and add .env to .gitignore."},
            "defaultConfiguration": {"level": "error"},
        },
        {
            "id": "LLMKG101",
            "name": "MCP Config Hardcoded Provider Key",
            "shortDescription": {"text": "Hardcoded LLM/API credential inside MCP configuration"},
            "help": {"text": "Inject MCP credentials via environment variables rather than literal strings."},
            "defaultConfiguration": {"level": "error"},
        },
        {
            "id": "LLMKG102",
            "name": "MCP Config High-Entropy Credential",
            "shortDescription": {"text": "High-entropy secret literal inside MCP configuration"},
            "help": {"text": "Replace literal credential with an environment variable reference."},
            "defaultConfiguration": {"level": "error"},
        },
    ]

    sarif_results = []
    for f in findings:
        msg = f"{f.provider} detected ({f.masked}). {f.remediation}"
        if f.context_path:
            msg = f"[{f.context_path}] {msg}"
        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": f.severity,
                "message": {"text": msg},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {
                                "startLine": max(1, f.line),
                                "startColumn": max(1, f.column),
                            },
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "llm-keyguard",
                        "version": version,
                        "informationUri": "https://pypi.org/project/llm-keyguard/",
                        "rules": rule_catalog,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
