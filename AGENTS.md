# AGENTS.md

BadDNS detects subdomain takeovers and DNS misconfigurations. It also runs as a BBOT module.

## Toolchain

| Concern | This repository |
|---|---|
| Language | Python 3.10 through 3.14 |
| Package manager | uv |
| Lint and format | ruff, pinned in pyproject.toml |
| Tests | pytest with pytest-asyncio, pytest-httpx, pyfakefs |

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



### Module System

All detection logic lives in `baddns/modules/`. Each module is a class inheriting from `BadDNS_base` (defined in `baddns/base.py`). Modules are auto-discovered and dynamically imported by `baddns/__init__.py`: just drop a new `.py` file in `modules/` and it's available.

The 10 modules: **CNAME** (dangling CNAMEs), **NS** (dangling nameservers), **MX** (dangling mail exchangers), **NSEC** (NSEC walking for subdomain enumeration), **TXT** (hijackable domains in TXT records), **references** (hijackable domains in HTML/headers), **zonetransfer** (AXFR vulnerability), **DMARC** (missing/misconfigured DMARC records), **MTA-STS** (MTA-STS misconfigurations and dangling mta-sts subdomains), **WILDCARD** (wildcard DNS records enabling domain-wide takeover).

### Signature-Driven Detection

Signatures are YAML files in `baddns/signatures/` (~100 files). Each signature defines a service name, detection mode (`http`, `dns_nxdomain`, `dns_nosoa`), identifier patterns (cnames, IPs, nameservers), and HTTP matcher rules. The `Signature` class (`baddns/lib/signature.py`) loads them, and `Matcher` (`baddns/lib/matcher.py`) evaluates HTTP responses against matcher rules.

### Core Libraries (`baddns/lib/`)

- **DNSManager** (`dnsmanager.py`): async DNS resolution with retry, CNAME chain following, multi-record-type dispatch
- **HttpManager** (`httpmanager.py`): fires 4 async HTTP requests per target (http/https × follow/deny redirects)
- **WhoisManager** (`whoismanager.py`): async WHOIS lookups, checks domain registration/expiration
- **DnsWalk** (`dnswalk.py`): recursive nameserver tracing from root servers, used by NS module
- **Finding** (`findings.py`): structured output with confidence levels (CONFIRMED/PROBABLE/POSSIBLE/UNLIKELY)

### Execution Flow

CLI (`baddns/cli.py`) -> validates args -> loads signatures -> instantiates selected modules -> calls each module's async `dispatch()` -> collects `Finding` objects -> outputs JSON.

### Test infrastructure

Tests are in `tests/` and heavily mock DNS/HTTP/WHOIS. Key test infrastructure:

- `tests/conftest.py`: shared fixtures (`mock_dispatch_whois`, `cached_suffix_list`, `configure_mock_resolver`)
- `tests/helpers.py`: `MockResolver`, `MockDNSWalk`, `DnsWalkHarness` for DNS mocking
- Tests use `pytest-asyncio` for async, `pytest-httpx` for HTTP mocking, `pyfakefs` for filesystem mocking

