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
uv run pytest tests/cname_test.py::test_name -v
```

## Lint and format

```bash
uv run ruff format --check .
uv run ruff check .
uv run ruff format .
```

## Running the CLI

```bash
uv run baddns example.com
uv run baddns -m CNAME,NS example.com    # specific modules
uv run baddns -d example.com             # debug logging
uv run baddns -D example.com             # direct mode (CNAME only)
uv run baddns -h                         # all options
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

### Modules

Modules live in `baddns/modules/`, subclass `BadDNS_base` (`baddns/base.py`), and are auto-discovered by `baddns/__init__.py`. Adding a file there registers it. `baddns -l` is the source of truth; at the time of writing:

- **CNAME**: dangling CNAMEs, interrogated for takeover
- **NS**: dangling nameservers
- **MX**: dangling mail exchangers, base domains checked for availability
- **NSEC**: subdomain enumeration by NSEC walking
- **TXT**: hijackable domains in TXT records
- **references**: hijackable domains in HTML and headers
- **zonetransfer**: AXFR
- **DELEGATION**: dangling `_acme-challenge`, `_dmarc`, and common DKIM selector CNAMEs
- **DMARC**, **SPF**, **MTA-STS**: email misconfigurations. These subclass `BadDNS_email_base` (`baddns/lib/email_base.py`) and are skipped when the domain has no MX, unless `--disable-mx-gate` is set.
- **WILDCARD**: wildcard records that enable domain-wide takeover

### Signatures

Signatures are YAML in `baddns/signatures/`, loaded by `baddns/lib/loader.py` into `BadDNSSignature` (`baddns/lib/signature.py`, valid modes in `BadDNSSignature.validModes`) and matched against HTTP responses by `Matcher` (`baddns/lib/matcher.py`). Identifiers (cnames, not_cnames, ips, nameservers) are `word` or `regex`. `negative_*` signatures suppress findings for known non-exploitable services; `--disable-negative-signatures` turns them off.

Most signatures are imported from nuclei-templates and dnsReaper by the SignatureBot (`baddns/scripts/readsources.py`, `.github/workflows/read-sources.yml`), which opens one PR per changed signature against `dev`. Format, hand-tuned fields, and how to drop a signature for good are in `docs/signatures.md`. Close an unwanted bot PR with the `signature-blocked` label: a plain close is re-proposed on the next daily run.

### Core libraries (`baddns/lib/`)

- `DNSManager` (`dnsmanager.py`): async resolution on blastdns, CNAME chain following
- `HttpManager` (`httpmanager.py`): four requests per target (http/https, with and without redirects) on blasthttp, plus TLS handshake failure detection
- `WhoisManager` (`whoismanager.py`): WHOIS lookups, registration and expiry checks
- `DnsWalk` (`dnswalk.py`): nameserver tracing from the roots, used by NS
- `Finding` (`findings.py`): output; levels in `CONFIDENCE_LEVELS` and `SEVERITY_LEVELS`, filtered by `--min-confidence` and `--min-severity`

### Flow

`baddns/cli.py` validates args, loads signatures, instantiates the selected modules, awaits each `dispatch()`, and prints `Finding` objects as JSON.

### Tests

Tests mock DNS, HTTP, and WHOIS.

- `tests/conftest.py`: `mock_http` (a `MockBlastHTTP` from `baddns/mock_blasthttp.py`, passed to modules as `http_client=`), `configure_mock_resolver`, `mock_dispatch_whois`, `cached_suffix_list`, `dnswalk_harness`
- `tests/helpers.py`: `create_mock_client`, `MockDNSWalk`, `DnsWalkHarness`
- pytest-asyncio for async tests, pyfakefs for the filesystem

### Branches and releases

- `dev`: active development; PRs target it.
- `stable`: the default branch and release line.
- The version lives only in `baddns/__version__.py` (hatchling reads it). A push to `stable` whose version differs from the latest tag publishes to PyPI and tags the release.
- Do not add `Co-Authored-By` lines to commit messages.
