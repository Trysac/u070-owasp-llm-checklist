# owasp-llm-checklist

[![PyPI version](https://img.shields.io/pypi/v/trysac-owasp-llm-checklist)](https://pypi.org/project/trysac-owasp-llm-checklist/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-owasp-llm-checklist)](LICENSE)
[![CI](https://github.com/Trysac/u070-owasp-llm-checklist/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u070-owasp-llm-checklist/actions/workflows/ci.yml)

Static checklist for the OWASP Top 10 for LLM Applications 2025 over a repository: ten pattern hints plus answered questions, as Markdown or JSON

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-owasp-llm-checklist
# or
uv add trysac-owasp-llm-checklist
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import owasp_llm_checklist

# normalize() trims surrounding whitespace and lower-cases the text.
print(owasp_llm_checklist.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    owasp_llm_checklist.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
