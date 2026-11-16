"""Comprehensive unit tests for llm-keyguard."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from llm_keyguard import (
    __version__,
    audit_mcp_file,
    build_sarif_report,
    generate_env_example,
    harden_gitignore,
    install_pre_commit_hook,
    scan_git_history,
    scan_git_staged,
    scan_path,
    scan_text,
)
from llm_keyguard.cli import main as cli_main


def _rm_readonly(func, path, _exc_info):
    os.chmod(path, stat.S_IWRITE)
    func(path)


class TestLLMKeyguard(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="llm_keyguard_test_"))

    def tearDown(self) -> None:
        if self.tmp_dir.exists():
            shutil.rmtree(self.tmp_dir, onerror=_rm_readonly)

    def test_detects_major_llm_provider_tokens(self) -> None:
        samples = [
            ("LLMKG001", "sk-" + "proj-" + "A9k2M7pQ4xR8vL1nW5zT3bY6cH0jF9dG2sK8mV4p"),
            ("LLMKG003", "sk-" + "ant-api03-" + "B8m3N9qR5yS1wM2pX6aU4cZ7dJ1kG0eH3tL9nW5q"),
            ("LLMKG004", "AIza" + "Sy" + "D9k2M7pQ4xR8vL1nW5zT3bY6cH0jF9dG2"),
            ("LLMKG005", "gsk_" + "C7n4P8rS6zT2xN3qY7bV5dA8eK2mH1fJ4uM0pX6rW9"),
            ("LLMKG006", "sk-or-" + "v1-" + "9f4c8a2e7b1d6053c4e9a8f2b7d16053e8c4a9f27b1d6053c9e4a8f2b7d16053"),
            ("LLMKG007", "hf_" + "E9p5Q0sT7aU3yP4rZ8cW6eB9fL3nJ2gK5v"),
            ("LLMKG009", "pplx-" + "F0q6R1tU8bV4zQ5sA9dX7fC0gM4pK3hL6wN8rT2yU5"),
            ("LLMKG012", "pcsk_" + "G1r7S2uV9cW5aR6tB0eY8gD1hN5qL4jM7xP9sU3zV6"),
            ("LLMKG016", "ghp_" + "H2s8T3vW0dX6bS7uC1fZ9hE2jP6rM5kN8yQ0tV4a"),
        ]
        for expected_rule, token in samples:
            with self.subTest(rule=expected_rule):
                hits = scan_text(f'API_KEY = "{token}"\n', file_label="app.py")
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0].rule_id, expected_rule)
                self.assertNotIn(token, hits[0].masked)

    def test_ignores_placeholders_and_inline_suppressions(self) -> None:
        placeholder_code = (
            'OPENAI_API_KEY = "sk-proj-your_openai_api_key_placeholder_here_12345"\n'
            'LOW_ENTROPY = "sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
        )
        self.assertEqual(scan_text(placeholder_code), [])

        suppressed_tok = "sk-" + "proj-" + "A9k2M7pQ4xR8vL1nW5zT3bY6cH0jF9dG2sK8mV4p"
        suppressed_line = f'FIXTURE = "{suppressed_tok}"  # keyguard: ignore\n'
        self.assertEqual(scan_text(suppressed_line), [])

    def test_mcp_config_auditor_pinpoints_json_path(self) -> None:
        tok = "sk-" + "proj-" + "K4m9P2rT7wY1zB5dF8hJ0lN3qS6uX9aC2eG5iL8o"
        mcp_file = self.tmp_dir / ".mcp.json"
        mcp_payload = {
            "mcpServers": {
                "openai-tools": {
                    "command": "npx",
                    "args": ["-y", "@example/mcp-server"],
                    "env": {
                        "OPENAI_API_KEY": tok,
                        "SAFE_VAR": "${env:OPENAI_ORG_ID}",
                    },
                }
            }
        }
        mcp_file.write_text(json.dumps(mcp_payload, indent=2), encoding="utf-8")

        findings = audit_mcp_file(mcp_file)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "LLMKG101")
        self.assertEqual(findings[0].context_path, "mcpServers.openai-tools.env.OPENAI_API_KEY")

    def test_sarif_report_structure(self) -> None:
        tok = "AIza" + "Sy" + "D9k2M7pQ4xR8vL1nW5zT3bY6cH0jF9dG2"
        hits = scan_text(f"key={tok}", file_label="config.py")
        sarif = build_sarif_report(hits, version=__version__)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "LLMKG004")

    def test_gitignore_hardening_and_env_example(self) -> None:
        added = harden_gitignore(self.tmp_dir)
        self.assertIn(".env", added)
        self.assertIn("!.env.example", added)
        # Idempotency check
        self.assertEqual(harden_gitignore(self.tmp_dir), [])

        env_src = self.tmp_dir / ".env"
        tok = "sk-" + "proj-" + "Z9k2M7pQ4xR8vL1nW5zT3bY6cH0jF9dG2sK8mV4p"
        env_src.write_text(
            f"# App settings\nOPENAI_API_KEY={tok}\nPORT=8080\nAPI_BASE=https://api.openai.com/v1\n",
            encoding="utf-8",
        )
        env_out = self.tmp_dir / ".env.example"
        mapping = generate_env_example(env_src, env_out)
        rendered = env_out.read_text(encoding="utf-8")
        self.assertNotIn(tok, rendered)
        self.assertEqual(mapping["OPENAI_API_KEY"], "your_openai_api_key_here")
        self.assertEqual(mapping["PORT"], "8080")

    def test_git_staged_and_history_scanning(self) -> None:
        subprocess.run(["git", "init"], cwd=str(self.tmp_dir), check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "dev@example.com"], cwd=str(self.tmp_dir), check=True)
        subprocess.run(["git", "config", "user.name", "Dev"], cwd=str(self.tmp_dir), check=True)

        hook_file = install_pre_commit_hook(self.tmp_dir)
        self.assertTrue(hook_file.is_file())

        # Clean file staged -> 0 findings
        clean_py = self.tmp_dir / "main.py"
        clean_py.write_text("print('clean')\n", encoding="utf-8")
        subprocess.run(["git", "add", "main.py"], cwd=str(self.tmp_dir), check=True)
        self.assertEqual(scan_git_staged(self.tmp_dir), [])
        subprocess.run(["git", "commit", "-m", "initial"], cwd=str(self.tmp_dir), check=True, capture_output=True)

        # Leaked token staged -> blocked
        leaked_tok = "gsk_" + "C7n4P8rS6zT2xN3qY7bV5dA8eK2mH1fJ4uM0pX6rW9"
        leak_py = self.tmp_dir / "client.py"
        leak_py.write_text(f'GROQ = "{leaked_tok}"\n', encoding="utf-8")
        subprocess.run(["git", "add", "client.py"], cwd=str(self.tmp_dir), check=True)
        staged_hits = scan_git_staged(self.tmp_dir)
        self.assertEqual(len(staged_hits), 1)
        self.assertEqual(staged_hits[0].rule_id, "LLMKG005")

        # Commit bypassing hook (-n) to verify git history scanner catches past leaks
        subprocess.run(["git", "commit", "-n", "-m", "oops"], cwd=str(self.tmp_dir), check=True, capture_output=True)
        hist_hits = scan_git_history(self.tmp_dir, max_commits=5)
        self.assertEqual(len(hist_hits), 1)
        self.assertEqual(hist_hits[0].rule_id, "LLMKG005")

    def test_cli_scan_exit_codes(self) -> None:
        clean_file = self.tmp_dir / "ok.py"
        clean_file.write_text("x = 42\n", encoding="utf-8")
        self.assertEqual(cli_main(["scan", str(clean_file)]), 0)

        tok = "AIza" + "Sy" + "D9k2M7pQ4xR8vL1nW5zT3bY6cH0jF9dG2"
        bad_file = self.tmp_dir / "bad.py"
        bad_file.write_text(f'k = "{tok}"\n', encoding="utf-8")
        self.assertEqual(cli_main(["scan", str(bad_file)]), 1)
        self.assertEqual(len(scan_path(self.tmp_dir)), 1)


if __name__ == "__main__":
    unittest.main()
