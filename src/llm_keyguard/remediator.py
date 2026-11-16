"""Repository remediation utilities (.gitignore hardening, .env.example, and Git hooks)."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Dict, List

GITIGNORE_ENTRIES: List[str] = [
    ".env",
    ".env.*",
    "!.env.example",
    "!.env.sample",
    "!.env.template",
    "*.pem",
    "*.key",
    "*credentials*.json",
    "*client_secret*.json",
]


def harden_gitignore(repo_dir: Path) -> List[str]:
    """Ensure .gitignore protects .env and secret key files while allowing .env.example."""
    gitignore_path = repo_dir / ".gitignore"
    existing = gitignore_path.read_text(encoding="utf-8", errors="ignore") if gitignore_path.exists() else ""
    present = {ln.strip() for ln in existing.splitlines() if ln.strip()}
    missing = [rule for rule in GITIGNORE_ENTRIES if rule not in present]
    if not missing:
        return []

    header = "# llm-keyguard secret protection"
    block = "\n".join([header] + missing) + "\n"
    updated = f"{existing.rstrip()}\n\n{block}" if existing.strip() else block
    gitignore_path.write_text(updated, encoding="utf-8")
    return missing


def install_pre_commit_hook(repo_dir: Path) -> Path:
    """Install a lightweight Git pre-commit hook invoking `llm-keyguard staged`."""
    hooks_dir = repo_dir / ".git" / "hooks"
    if not hooks_dir.is_dir():
        raise FileNotFoundError(f"No .git/hooks directory found under {repo_dir}")

    hook_path = hooks_dir / "pre-commit"
    py_exe = Path(sys.executable).as_posix()
    script = (
        "#!/bin/sh\n"
        "# Installed by llm-keyguard\n"
        f'"{py_exe}" -m llm_keyguard.cli staged\n'
        "exit $?\n"
    )
    hook_path.write_text(script, encoding="utf-8", newline="\n")
    try:
        mode = hook_path.stat().st_mode
        hook_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass
    return hook_path


def generate_env_example(dotenv_path: Path, output_path: Path) -> Dict[str, str]:
    """Create a sanitized .env.example from a local .env file without exposing secret values."""
    if not dotenv_path.is_file():
        raise FileNotFoundError(f"Source .env file not found: {dotenv_path}")

    out_lines: List[str] = []
    sanitized_map: Dict[str, str] = {}

    for raw_line in dotenv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            out_lines.append(raw_line)
            continue
        key, val = stripped.split("=", 1)
        key_clean = key.strip()
        val_clean = val.strip().strip('"').strip("'")
        placeholder = _placeholder_for_key(key_clean, val_clean)
        sanitized_map[key_clean] = placeholder
        out_lines.append(f"{key_clean}={placeholder}")

    output_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    return sanitized_map


def _placeholder_for_key(key: str, val: str) -> str:
    upper = key.upper()
    if any(tok in upper for tok in ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PAT", "CREDENTIAL")):
        return f"your_{key.lower()}_here"
    if val.startswith(("http://", "https://")):
        return val
    if val.lower() in {"true", "false", "0", "1", "development", "production"} or val.isdigit():
        return val
    return f"your_{key.lower()}_here"
