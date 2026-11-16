"""Core file, Git diff/history, and MCP configuration scanners."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from .signatures import (
    INLINE_IGNORE_MARKERS,
    RULES,
    is_likely_placeholder,
    mask_secret,
    shannon_entropy,
)

SCANNABLE_EXTENSIONS: Set[str] = {
    ".py", ".pyi", ".ipynb", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".rb", ".go", ".rs",
    ".java", ".kt", ".cs", ".php", ".swift", ".md", ".txt", ".env",
}

DEFAULT_SKIP_DIRS: Set[str] = {
    ".git", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".venv", "venv", "env", ".tox", "dist", "build", ".next",
}

MCP_CONFIG_FILENAMES: Set[str] = {
    "mcp.json",
    ".mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
    "cline_mcp_settings.json",
}

SENSITIVE_ENV_KEY_HINTS = (
    "api_key", "apikey", "secret", "token", "password", "passwd", "private_key", "access_key",
)


@dataclass(frozen=True)
class Finding:
    """Single verified secret or credential policy violation."""

    rule_id: str
    provider: str
    severity: str
    file: str
    line: int
    column: int
    masked: str
    entropy: float
    remediation: str
    context_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def is_dotenv_secret_file(path: Path) -> bool:
    """Return True if path is a live .env file (excluding safe templates like .env.example)."""
    name = path.name.lower()
    if name in {".env.example", ".env.sample", ".env.template", ".env.schema"}:
        return False
    return name == ".env" or name.startswith(".env.")


def scan_text(
    text: str,
    file_label: str = "<memory>",
    extra_ignore_patterns: Optional[Sequence[str]] = None,
) -> List[Finding]:
    """Scan raw text line-by-line and return verified secret findings."""
    findings: List[Finding] = []
    for line_idx, line in enumerate(text.splitlines(), start=1):
        if len(line) > 8192:
            continue
        low_line = line.lower()
        if any(marker in low_line for marker in INLINE_IGNORE_MARKERS):
            continue
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                candidate = match.group(0)
                if is_likely_placeholder(candidate):
                    continue
                if extra_ignore_patterns and any(pat in candidate for pat in extra_ignore_patterns):
                    continue
                ent = shannon_entropy(candidate)
                if ent < rule.min_entropy:
                    continue
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        provider=rule.provider,
                        severity=rule.severity,
                        file=file_label,
                        line=line_idx,
                        column=match.start() + 1,
                        masked=mask_secret(candidate),
                        entropy=round(ent, 2),
                        remediation=rule.remediation,
                    )
                )
    return findings


def scan_file(
    path: Path,
    include_dotenv: bool = False,
    max_bytes: int = 3_000_000,
) -> List[Finding]:
    """Scan a single file on disk."""
    if not path.is_file():
        return []
    if is_dotenv_secret_file(path) and not include_dotenv:
        return []
    suffix = path.suffix.lower()
    if suffix not in SCANNABLE_EXTENSIONS and path.name not in MCP_CONFIG_FILENAMES:
        return []
    try:
        if path.stat().st_size > max_bytes:
            return []
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return scan_text(content, file_label=path.as_posix())


def iter_files(root: Path, skip_dirs: Optional[Set[str]] = None) -> Iterable[Path]:
    """Yield files recursively while pruning ignored build/dependency directories."""
    if root.is_file():
        yield root
        return
    excluded = skip_dirs if skip_dirs is not None else DEFAULT_SKIP_DIRS
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in excluded]
        base = Path(dirpath)
        for fname in sorted(filenames):
            yield base / fname


def scan_path(root: Path, include_dotenv: bool = False) -> List[Finding]:
    """Scan a directory tree or single file for hardcoded secrets and MCP leaks."""
    results: List[Finding] = []
    seen_keys: Set[tuple] = set()
    for file_path in iter_files(root):
        for f in scan_file(file_path, include_dotenv=include_dotenv):
            dedup = (f.file, f.line, f.column, f.rule_id)
            if dedup not in seen_keys:
                seen_keys.add(dedup)
                results.append(f)
        if _looks_like_mcp_config(file_path):
            for mf in audit_mcp_file(file_path):
                dedup = (mf.file, mf.line, mf.rule_id, mf.context_path)
                if dedup not in seen_keys:
                    seen_keys.add(dedup)
                    results.append(mf)
    return results


def _looks_like_mcp_config(path: Path) -> bool:
    name = path.name.lower()
    if name in MCP_CONFIG_FILENAMES:
        return True
    parts = {p.lower() for p in path.parts}
    return name == "mcp.json" or (".cursor" in parts and name.endswith(".json"))


def _walk_json_secrets(
    node: Any,
    key_path: str,
    file_label: str,
    raw_lines: List[str],
    out: List[Finding],
) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            sub_path = f"{key_path}.{k}" if key_path else str(k)
            _walk_json_secrets(v, sub_path, file_label, raw_lines, out)
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            _walk_json_secrets(item, f"{key_path}[{idx}]", file_label, raw_lines, out)
    elif isinstance(node, str):
        val = node.strip()
        if not val or val.startswith("${") or val.startswith("$env:") or val.startswith("<"):
            return
        leaf_key = key_path.rsplit(".", 1)[-1].lower()
        is_sensitive_key = any(h in leaf_key for h in SENSITIVE_ENV_KEY_HINTS)
        # Check known provider signatures first
        direct = scan_text(val, file_label=file_label)
        line_no = _locate_line_number(raw_lines, val)
        if direct:
            for d in direct:
                out.append(
                    Finding(
                        rule_id="LLMKG101",
                        provider=f"MCP Config Hardcoded {d.provider}",
                        severity="error",
                        file=file_label,
                        line=line_no,
                        column=1,
                        masked=d.masked,
                        entropy=d.entropy,
                        remediation=f"Replace literal in '{key_path}' with '${{env:{leaf_key.upper()}}}' or OS env injection.",
                        context_path=key_path,
                    )
                )
        elif is_sensitive_key and len(val) >= 16 and not is_likely_placeholder(val):
            ent = shannon_entropy(val)
            if ent >= 3.50:
                out.append(
                    Finding(
                        rule_id="LLMKG102",
                        provider="MCP Config High-Entropy Credential",
                        severity="error",
                        file=file_label,
                        line=line_no,
                        column=1,
                        masked=mask_secret(val),
                        entropy=round(ent, 2),
                        remediation=f"Avoid committing literal credentials in '{key_path}'; reference an environment variable.",
                        context_path=key_path,
                    )
                )


def _locate_line_number(lines: List[str], needle: str) -> int:
    short_needle = needle[:24]
    for idx, ln in enumerate(lines, start=1):
        if short_needle in ln:
            return idx
    return 1


def audit_mcp_file(path: Path) -> List[Finding]:
    """Parse an MCP configuration JSON file and detect hardcoded server credentials."""
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore")
        parsed = json.loads(raw)
    except Exception:
        return []
    findings: List[Finding] = []
    _walk_json_secrets(parsed, "", path.as_posix(), raw.splitlines(), findings)
    return findings


def audit_mcp_configs(root: Path) -> List[Finding]:
    """Find and audit all MCP configuration files under root."""
    out: List[Finding] = []
    for fp in iter_files(root):
        if _looks_like_mcp_config(fp):
            out.extend(audit_mcp_file(fp))
    return out


def scan_git_staged(repo_dir: Path) -> List[Finding]:
    """Scan files currently staged in Git (`git diff --cached`) and block staged .env files."""
    proc = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return []

    findings: List[Finding] = []
    for rel in proc.stdout.splitlines():
        rel_clean = rel.strip()
        if not rel_clean:
            continue
        full_path = repo_dir / rel_clean
        if is_dotenv_secret_file(full_path):
            findings.append(
                Finding(
                    rule_id="LLMKG000",
                    provider="Staged .env File",
                    severity="error",
                    file=full_path.as_posix(),
                    line=1,
                    column=1,
                    masked=full_path.name,
                    entropy=0.0,
                    remediation="Unstage with `git restore --staged .env` and add `.env` to `.gitignore`.",
                )
            )
            continue
        findings.extend(scan_file(full_path, include_dotenv=True))
        if _looks_like_mcp_config(full_path):
            findings.extend(audit_mcp_file(full_path))
    return findings


def scan_git_history(repo_dir: Path, max_commits: int = 50) -> List[Finding]:
    """Scan recent Git commit patches (`git log -p`) for historically leaked keys."""
    proc = subprocess.run(
        ["git", "log", f"-n{int(max_commits)}", "-p", "--no-color"],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout:
        return []

    findings: List[Finding] = []
    current_commit = "HEAD"
    current_file = "<git-log>"
    added_line_no = 0

    for line in proc.stdout.splitlines():
        if line.startswith("commit "):
            current_commit = line.split()[1][:10]
        elif line.startswith("+++ b/"):
            current_file = f"{line[6:]}@{current_commit}"
            added_line_no = 0
        elif line.startswith("+") and not line.startswith("+++"):
            added_line_no += 1
            for hit in scan_text(line[1:], file_label=current_file):
                findings.append(
                    Finding(
                        rule_id=hit.rule_id,
                        provider=hit.provider,
                        severity=hit.severity,
                        file=current_file,
                        line=added_line_no,
                        column=hit.column,
                        masked=hit.masked,
                        entropy=hit.entropy,
                        remediation=hit.remediation,
                        context_path=f"commit:{current_commit}",
                    )
                )
    return findings
