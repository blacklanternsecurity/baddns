# AGENTS.md

BadDNS detects subdomain takeovers and DNS misconfigurations. It also runs as a BBOT module.

## Toolchain

| Concern | This repository |
|---|---|
| Language | Python, `requires-python` in pyproject.toml |
| Package manager | uv |
| Lint and format | ruff, version in the `dev` group of pyproject.toml |
| Tests | pytest, plugins in the `dev` group of pyproject.toml |

## Setup

```bash
uv sync --group dev
```

## Tests

```bash
uv run pytest
uv run pytest tests/cname_test.py -v
```

## Standards

Org-wide, in [blacklanternsecurity/.github/standards](https://github.com/blacklanternsecurity/.github/tree/main/standards). Read the one your task touches, not all of them.

| Document | Read it when |
|---|---|
| [principles.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/principles.md) | Always |
| [toolchain.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/toolchain.md) | Touching dependencies, linting, formatting, or language versions |
| [git.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/git.md) | Branching, commit messages, opening or reviewing a pull request |
| [rfc.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/rfc.md) | A change needs agreement before work starts, or an RFC is ending |
| [testing.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/testing.md) | Writing or changing tests, or anything that has them |
| [ci.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/ci.md) | Touching a workflow, an action pin, or a permissions block |
| [releases.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/releases.md) | Versioning, tagging, or publishing |
| [repository-setup.md](https://github.com/blacklanternsecurity/.github/blob/main/standards/repository-setup.md) | Creating a repository, or auditing one |

Never restate a standard here. If this file and a standard disagree, the standard wins and this file is the bug.

## Repository specifics

- Modules live in `baddns/modules/`, subclass `BadDNS_base` (`baddns/base.py`), and are auto-discovered by `baddns/__init__.py`. Adding a file there registers it. `baddns -l` lists them.
- Signatures are YAML in `baddns/signatures/`, loaded by `baddns/lib/signature.py` (valid modes in `Signature.validModes`) and matched by `baddns/lib/matcher.py`.
- Signatures with `source: dnsreaper` or `source: nucleitemplates` are regenerated daily from upstream by `read-sources.yml`. Don't edit them. New or hand-maintained signatures use `source: self`.
- A signature that fails validation is logged and skipped, not raised, and the test suite only checks that at least one signature loads. Check a new signature with `uv run python baddns/scripts/signaturetest.py <file>`, which validates it and live-tests `http` signatures against random subdomains of their CNAMEs.
- `negative_signature: true` marks a known-benign target (parking pages, registrar nameservers) and suppresses the generic finding the CNAME and NS modules would otherwise report. These are the `negative_*.yml` files.
- Finding confidence levels: `CONFIDENCE_LEVELS` in `baddns/lib/findings.py`.
- Flow: `baddns/cli.py` loads signatures, instantiates modules, awaits each `dispatch()`, prints `Finding` objects as JSON.
- Tests mock DNS, HTTP, and WHOIS. Shared fixtures are in `tests/conftest.py`, DNS mocks in `tests/helpers.py`.
