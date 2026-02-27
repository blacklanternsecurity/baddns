# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BadDNS is a Python tool for detecting subdomain takeovers and DNS issues (dangling CNAME/NS/MX records, NSEC walks, zone transfers, HTML reference hijacking). It's also used as a BBOT module.

## Common Commands

### Install dependencies
```bash
pip install poetry
poetry install
```

### Run all tests
```bash
poetry run pytest --exitfirst --disable-warnings --log-cli-level=DEBUG
```

### Run a single test file
```bash
poetry run pytest tests/cname_test.py -v
```

### Run a single test
```bash
poetry run pytest tests/cname_test.py::test_cname_function_name -v
```

### Lint
```bash
# Formatting check (line-length: 119)
black --check .

# Static analysis
flake8 --select F,E722 --ignore F403,F405,F541 --per-file-ignores="*/__init__.py:F401,F403"
```

### Format code
```bash
black .
```

### Run the CLI
```bash
poetry run baddns example.com
poetry run baddns -m CNAME,NS example.com    # specific modules
poetry run baddns -d example.com              # debug mode
poetry run baddns --direct example.com        # direct mode (CNAME only)
```

## Architecture

### Module System

All detection logic lives in `baddns/modules/`. Each module is a class inheriting from `BadDNS_base` (defined in `baddns/base.py`). Modules are auto-discovered and dynamically imported by `baddns/__init__.py` — just drop a new `.py` file in `modules/` and it's available.

The 7 modules: **CNAME** (dangling CNAMEs), **NS** (dangling nameservers), **MX** (dangling mail exchangers), **NSEC** (NSEC walking for subdomain enumeration), **TXT** (hijackable domains in TXT records), **references** (hijackable domains in HTML/headers), **zonetransfer** (AXFR vulnerability).

### Signature-Driven Detection

Signatures are YAML files in `baddns/signatures/` (~100 files). Each signature defines a service name, detection mode (`http`, `dns_nxdomain`, `dns_nosoa`), identifier patterns (cnames, IPs, nameservers), and HTTP matcher rules. The `Signature` class (`baddns/lib/signature.py`) loads them, and `Matcher` (`baddns/lib/matcher.py`) evaluates HTTP responses against matcher rules.

### Core Libraries (`baddns/lib/`)

- **DNSManager** (`dnsmanager.py`) — async DNS resolution with retry, CNAME chain following, multi-record-type dispatch
- **HttpManager** (`httpmanager.py`) — fires 4 async HTTP requests per target (http/https × follow/deny redirects)
- **WhoisManager** (`whoismanager.py`) — async WHOIS lookups, checks domain registration/expiration
- **DnsWalk** (`dnswalk.py`) — recursive nameserver tracing from root servers, used by NS module
- **Finding** (`findings.py`) — structured output with confidence levels (CONFIRMED/PROBABLE/POSSIBLE/UNLIKELY)

### Execution Flow

CLI (`baddns/cli.py`) → validates args → loads signatures → instantiates selected modules → calls each module's async `dispatch()` → collects `Finding` objects → outputs JSON.

## Testing

Tests are in `tests/` and heavily mock DNS/HTTP/WHOIS. Key test infrastructure:

- `tests/conftest.py` — shared fixtures (`mock_dispatch_whois`, `cached_suffix_list`, `configure_mock_resolver`)
- `tests/helpers.py` — `MockResolver`, `MockDNSWalk`, `DnsWalkHarness` for DNS mocking
- Tests use `pytest-asyncio` for async, `pytest-httpx` for HTTP mocking, `pyfakefs` for filesystem mocking

## Versioning

Version is tracked in **two places** in `pyproject.toml`:
- `tool.poetry.version` (e.g., `"1.13.0"`)
- `tool.poetry-dynamic-versioning.format` (e.g., `'1.13.{distance}'`)

Both must be updated together for releases. Publishing to PyPI happens automatically on push to `main` when the major.minor version changes.

## Git Workflow

- `main` branch — stable releases, auto-publishes to PyPI
- `dev` branch — active development, PRs target here
- Do not add "Co-Authored-By" lines to commit messages
