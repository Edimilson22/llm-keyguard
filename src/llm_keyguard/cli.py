"""Command-line interface for llm-keyguard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .remediator import generate_env_example, harden_gitignore, install_pre_commit_hook
from .sarif import build_sarif_report
from .scanner import (
    Finding,
    audit_mcp_configs,
    scan_git_history,
    scan_git_staged,
    scan_path,
)


def _emit_findings(findings: Sequence[Finding], fmt: str) -> None:
    if fmt == "json":
        payload = {
            "version": __version__,
            "count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2))
        return
    if fmt == "sarif":
        print(json.dumps(build_sarif_report(findings, version=__version__), indent=2))
        return

    if not findings:
        print("llm-keyguard: OK (0 exposed credentials found)")
        return

    print(f"llm-keyguard: BLOCKED ({len(findings)} credential issue(s) detected)", file=sys.stderr)
    for item in findings:
        ctx = f" [{item.context_path}]" if item.context_path else ""
        print(
            f"  [{item.rule_id}] {item.file}:{item.line}:{item.column}{ctx} -> "
            f"{item.provider}: {item.masked}",
            file=sys.stderr,
        )
        print(f"      Fix: {item.remediation}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="llm-keyguard",
        description="Zero-dependency secret scanner, MCP config auditor, and Git pre-commit guard for LLM & AI API keys.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a directory or file for hardcoded API keys and MCP leaks")
    p_scan.add_argument("target", nargs="?", default=".", help="Directory or file to scan (default: .)")
    p_scan.add_argument("--include-dotenv", action="store_true", help="Also scan local .env files")
    p_scan.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="Output format")

    p_staged = sub.add_parser("staged", help="Scan staged Git changes (for pre-commit hooks)")
    p_staged.add_argument("--repo", default=".", help="Git repository root (default: .)")
    p_staged.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="Output format")

    p_hist = sub.add_parser("history", help="Scan recent Git commit patches for leaked credentials")
    p_hist.add_argument("--repo", default=".", help="Git repository root (default: .)")
    p_hist.add_argument("-n", "--max-commits", type=int, default=50, help="Commits to inspect (default: 50)")
    p_hist.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="Output format")

    p_mcp = sub.add_parser("audit-mcp", help="Audit MCP configuration files for hardcoded credentials")
    p_mcp.add_argument("target", nargs="?", default=".", help="Directory or MCP file to inspect")
    p_mcp.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="Output format")

    p_init = sub.add_parser("init", help="Harden .gitignore and install Git pre-commit hook")
    p_init.add_argument("--repo", default=".", help="Target repository directory (default: .)")
    p_init.add_argument("--no-hook", action="store_true", help="Only update .gitignore without installing hook")

    p_env = sub.add_parser("env-example", help="Generate a safe .env.example from a local .env file")
    p_env.add_argument("--source", default=".env", help="Source .env file (default: .env)")
    p_env.add_argument("--output", default=".env.example", help="Destination template file (default: .env.example)")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        findings = scan_path(Path(args.target), include_dotenv=args.include_dotenv)
        _emit_findings(findings, args.format)
        return 1 if findings else 0

    if args.command == "staged":
        findings = scan_git_staged(Path(args.repo))
        _emit_findings(findings, args.format)
        return 1 if findings else 0

    if args.command == "history":
        findings = scan_git_history(Path(args.repo), max_commits=args.max_commits)
        _emit_findings(findings, args.format)
        return 1 if findings else 0

    if args.command == "audit-mcp":
        findings = audit_mcp_configs(Path(args.target))
        _emit_findings(findings, args.format)
        return 1 if findings else 0

    if args.command == "init":
        repo = Path(args.repo).resolve()
        added = harden_gitignore(repo)
        if added:
            print(f"llm-keyguard: added {len(added)} secret-protection rule(s) to {repo / '.gitignore'}")
        else:
            print(f"llm-keyguard: {repo / '.gitignore'} already hardened")
        if not args.no_hook:
            try:
                hook_path = install_pre_commit_hook(repo)
                print(f"llm-keyguard: installed Git pre-commit hook at {hook_path}")
            except FileNotFoundError as exc:
                print(f"llm-keyguard: skipped hook installation ({exc})", file=sys.stderr)
        return 0

    if args.command == "env-example":
        mapping = generate_env_example(Path(args.source), Path(args.output))
        print(f"llm-keyguard: generated {args.output} with {len(mapping)} sanitized variable(s)")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
