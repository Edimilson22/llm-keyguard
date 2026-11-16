"""Provider secret signatures and entropy helpers for llm-keyguard."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import List, Pattern


@dataclass(frozen=True)
class SecretRule:
    """Compiled detection rule for a specific AI, cloud, or developer token format."""

    rule_id: str
    provider: str
    severity: str
    pattern: Pattern[str]
    min_entropy: float
    remediation: str


RULES: List[SecretRule] = [
    SecretRule(
        rule_id="LLMKG001",
        provider="OpenAI API Key (Project/Service/Admin)",
        severity="error",
        pattern=re.compile(r"\bsk-(?:proj|svcacct|admin)-[0-9A-Za-z_\-]{32,}\b"),
        min_entropy=3.75,
        remediation="Move to OPENAI_API_KEY in .env and revoke leaked key at platform.openai.com/api-keys.",
    ),
    SecretRule(
        rule_id="LLMKG002",
        provider="OpenAI Legacy Secret Key",
        severity="error",
        pattern=re.compile(r"\bsk-[0-9A-Za-z]{20}T3BlbkFJ[0-9A-Za-z]{20}\b"),
        min_entropy=3.80,
        remediation="Rotate legacy OpenAI key immediately and switch to scoped project keys.",
    ),
    SecretRule(
        rule_id="LLMKG003",
        provider="Anthropic Claude API Key",
        severity="error",
        pattern=re.compile(r"\bsk-ant-(?:api\d+-)?[0-9A-Za-z_\-]{36,}\b"),
        min_entropy=3.80,
        remediation="Move to ANTHROPIC_API_KEY in .env and rotate in Anthropic Console.",
    ),
    SecretRule(
        rule_id="LLMKG004",
        provider="Google Gemini / Cloud API Key",
        severity="error",
        pattern=re.compile(r"\bAIzaSy[0-9A-Za-z_\-]{33}\b"),
        min_entropy=3.60,
        remediation="Move to GEMINI_API_KEY in .env and restrict/rotate key in Google AI Studio or GCP.",
    ),
    SecretRule(
        rule_id="LLMKG005",
        provider="Groq API Key",
        severity="error",
        pattern=re.compile(r"\bgsk_[0-9A-Za-z]{40,}\b"),
        min_entropy=3.80,
        remediation="Move to GROQ_API_KEY in .env and revoke in GroqCloud Console.",
    ),
    SecretRule(
        rule_id="LLMKG006",
        provider="OpenRouter API Key",
        severity="error",
        pattern=re.compile(r"\bsk-or-v1-[0-9A-Za-z]{48,}\b"),
        min_entropy=3.45,
        remediation="Move to OPENROUTER_API_KEY in .env and revoke at openrouter.ai/keys.",
    ),
    SecretRule(
        rule_id="LLMKG007",
        provider="HuggingFace Access Token",
        severity="error",
        pattern=re.compile(r"\bhf_[0-9A-Za-z]{30,}\b"),
        min_entropy=3.60,
        remediation="Move to HF_TOKEN in .env and invalidate token at huggingface.co/settings/tokens.",
    ),
    SecretRule(
        rule_id="LLMKG008",
        provider="Replicate API Token",
        severity="error",
        pattern=re.compile(r"\br8_[0-9A-Za-z]{34,}\b"),
        min_entropy=3.65,
        remediation="Move to REPLICATE_API_TOKEN in .env and rotate on replicate.com.",
    ),
    SecretRule(
        rule_id="LLMKG009",
        provider="Perplexity Sonar API Key",
        severity="error",
        pattern=re.compile(r"\bpplx-[0-9A-Za-z]{40,}\b"),
        min_entropy=3.65,
        remediation="Move to PERPLEXITY_API_KEY in .env and rotate in Perplexity API settings.",
    ),
    SecretRule(
        rule_id="LLMKG010",
        provider="Fireworks AI API Key",
        severity="error",
        pattern=re.compile(r"\bfw_[0-9A-Za-z]{24,}\b"),
        min_entropy=3.60,
        remediation="Move to FIREWORKS_API_KEY in .env and rotate at fireworks.ai.",
    ),
    SecretRule(
        rule_id="LLMKG011",
        provider="Tavily Search API Key",
        severity="error",
        pattern=re.compile(r"\btvly-(?:dev-|prod-)?[0-9A-Za-z]{28,}\b"),
        min_entropy=3.60,
        remediation="Move to TAVILY_API_KEY in .env and rotate in Tavily dashboard.",
    ),
    SecretRule(
        rule_id="LLMKG012",
        provider="Pinecone Vector DB Key",
        severity="error",
        pattern=re.compile(r"\bpcsk_[0-9A-Za-z_]{40,}\b"),
        min_entropy=3.70,
        remediation="Move to PINECONE_API_KEY in .env and rotate in Pinecone Console.",
    ),
    SecretRule(
        rule_id="LLMKG013",
        provider="LangSmith / LangChain API Key",
        severity="error",
        pattern=re.compile(r"\blsv2_(?:pt|sk)_[0-9A-Za-z_]{32,}\b"),
        min_entropy=3.60,
        remediation="Move to LANGSMITH_API_KEY in .env and revoke in LangSmith.",
    ),
    SecretRule(
        rule_id="LLMKG014",
        provider="ElevenLabs API Key",
        severity="error",
        pattern=re.compile(r"\bsk_[0-9a-f]{48}\b"),
        min_entropy=3.55,
        remediation="Move to ELEVENLABS_API_KEY in .env and rotate in ElevenLabs profile.",
    ),
    SecretRule(
        rule_id="LLMKG015",
        provider="Supabase Access Token",
        severity="error",
        pattern=re.compile(r"\bsbp_[0-9a-f]{40}\b"),
        min_entropy=3.55,
        remediation="Move to SUPABASE_ACCESS_TOKEN in .env and revoke in Supabase account.",
    ),
    SecretRule(
        rule_id="LLMKG016",
        provider="GitHub Personal Access Token",
        severity="error",
        pattern=re.compile(r"\b(?:gh[pousr]_[0-9A-Za-z]{36,}|github_pat_[0-9A-Za-z_]{50,})\b"),
        min_entropy=3.70,
        remediation="Revoke token immediately at github.com/settings/tokens.",
    ),
    SecretRule(
        rule_id="LLMKG017",
        provider="AWS Access Key ID",
        severity="error",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        min_entropy=3.25,
        remediation="Deactivate AWS IAM key in AWS Console and switch to IAM roles/OIDC.",
    ),
    SecretRule(
        rule_id="LLMKG018",
        provider="Stripe Live Secret Key",
        severity="error",
        pattern=re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"),
        min_entropy=3.65,
        remediation="Roll live Stripe key immediately in Stripe Dashboard.",
    ),
    SecretRule(
        rule_id="LLMKG019",
        provider="Slack Bot / User Token",
        severity="error",
        pattern=re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{24,}\b"),
        min_entropy=3.55,
        remediation="Revoke Slack token in Slack App Management.",
    ),
    SecretRule(
        rule_id="LLMKG020",
        provider="Private Cryptographic Key Block",
        severity="error",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        min_entropy=2.40,
        remediation="Remove private key file from repository and rotate keypair.",
    ),
]

PLACEHOLDER_SUBSTRINGS = (
    "your_",
    "your-",
    "example",
    "xxx",
    "00000000",
    "12345678",
    "abcdef012345",
    "replace_me",
    "changeme",
    "placeholder",
    "dummy",
    "sample_",
    "test_key",
    "fake_key",
)

INLINE_IGNORE_MARKERS = ("keyguard: ignore", "keyguard:ignore", "pragma: allowlist secret")


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = float(len(value))
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_likely_placeholder(value: str) -> bool:
    """Return True if a matched string looks like documentation or a test placeholder."""
    low = value.lower()
    if any(token in low for token in PLACEHOLDER_SUBSTRINGS):
        return True
    # Reject highly repetitive synthetic strings such as sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaa
    unique_ratio = len(set(value)) / max(1, len(value))
    return unique_ratio < 0.22


def mask_secret(value: str) -> str:
    """Mask a secret safely for terminal and CI logs without leaking raw credentials."""
    if len(value) <= 12:
        return "***REDACTED***"
    return f"{value[:6]}...{value[-4:]} (len={len(value)})"
