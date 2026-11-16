"""Public Python API for llm-keyguard."""

from __future__ import annotations

from .remediator import generate_env_example, harden_gitignore, install_pre_commit_hook
from .sarif import build_sarif_report
from .scanner import (
    Finding,
    audit_mcp_configs,
    audit_mcp_file,
    scan_file,
    scan_git_history,
    scan_git_staged,
    scan_path,
    scan_text,
)
from .signatures import RULES, SecretRule, mask_secret, shannon_entropy

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "Finding",
    "RULES",
    "SecretRule",
    "audit_mcp_configs",
    "audit_mcp_file",
    "build_sarif_report",
    "generate_env_example",
    "harden_gitignore",
    "install_pre_commit_hook",
    "mask_secret",
    "scan_file",
    "scan_git_history",
    "scan_git_staged",
    "scan_path",
    "scan_text",
    "shannon_entropy",
]
