# Contributing to llm-keyguard

Contributions adding new AI provider token formats, MCP configuration schemas, or false-positive reductions are welcome!

## Development Setup

```bash
git clone https://github.com/Edimilson22/llm-keyguard.git
cd llm-keyguard
pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

## Adding a New Provider Signature

1. Add a `SecretRule` entry in `src/llm_keyguard/signatures.py` with a tight prefix regex and realistic minimum Shannon entropy threshold.
2. Add both a synthetic high-entropy positive test (constructed dynamically in test code) and a low-entropy placeholder negative test in `tests/test_llm_keyguard.py`.
3. Ensure `llm-keyguard scan .` passes with `0` findings on the repository itself!
