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
uv run pytest tests/cname_test.py::test_cname_dnsnxdomain_azure_match -v
uv run pytest --exitfirst --disable-warnings --log-cli-level=DEBUG   # modules log their reasoning at DEBUG
```

## Lint and format

```bash
uv run ruff format --check .
uv run ruff check .
uv run ruff format .
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

### Modules and signatures

- Modules live in `baddns/modules/`, subclass `BadDNS_base` (`baddns/base.py`), and are auto-discovered: `baddns/__init__.py` imports every file in the directory, and `get_all_modules()` in `baddns/base.py` walks `__subclasses__` to enumerate them. Adding a file there registers it. `baddns -l` lists them. (`modules_loaded` in `__init__.py` is dead and nothing reads it; its direct-`__bases__` check would miss the email modules.)
- Email-related modules share `BadDNS_email_base` (`baddns/lib/email_base.py`) rather than subclassing `BadDNS_base` directly.
- Signatures are YAML in `baddns/signatures/`, loaded by `baddns/lib/loader.py` and parsed by `baddns/lib/signature.py`. Valid modes are `BadDNSSignature.validModes`; valid matcher types are `BadDNSSignature.validMatcherTypes`. Both are validated at load, so a malformed signature fails fast instead of silently never matching.
- A signature carries a service name, a detection mode, identifier patterns (cnames, ips, nameservers, not_cnames) that gate whether it is even tried, and matcher rules that decide the verdict. `baddns/lib/matcher.py` evaluates the matcher rules.
- A signature with `negative_signature: true` suppresses the generic finding for a service that looks dangling but is not claimable. The CNAME and NS modules honour it; `--disable-negative-signatures` turns it off. These files are named `negative_*` by convention, but the key is what counts.
- Finding confidence and severity levels: `CONFIDENCE_LEVELS` and `SEVERITY_LEVELS` in `baddns/lib/findings.py`.

### Core libraries (`baddns/lib/`)

These carry the I/O. Use them rather than talking to DNS or HTTP directly from a module.

| Module | Role |
|---|---|
| `dnsmanager.py` | `DNSManager` — async resolution with retry, CNAME chain following, multi-record-type dispatch. Distinguishes NXDOMAIN, NoAnswer and ERROR; a lookup that failed is not the same as a record that is absent. |
| `httpmanager.py` | `HttpManager` — `dispatchHttp()` fires the standard set of requests per target (http/https × follow/deny redirects), storing each result on its own attribute and `None` on failure. `skip_redirects=True` halves that. |
| `whoismanager.py` | `WhoisManager` — async WHOIS, used to spot unregistered and expiring domains. Results are cached per process. |
| `dnswalk.py` | `DnsWalk` — recursive nameserver tracing from the root servers, used by the NS module. |
| `findings.py` | `Finding` — the structured result every module returns, and the confidence/severity filtering behind `--min-confidence` and `--min-severity`. |
| `matcher.py` | `Matcher` — evaluates a signature's matcher rules against a response. |
| `errors.py` | The `BadDNSException` hierarchy. Raise these rather than bare exceptions. |

### Execution flow

`baddns/cli.py` validates arguments → loads signatures → instantiates the selected modules → awaits each module's `dispatch()` → collects `Finding` objects → prints JSON.

`dispatch()` returns `False` when a module has nothing to work with (no CNAME, wrong record shape), which is the common case and not an error. `analyze()` then turns what it found into findings.

### CLI

```bash
uv run baddns example.com
uv run baddns -l                              # list modules
uv run baddns -m CNAME,NS example.com         # only these modules
uv run baddns -d example.com                  # debug logging
uv run baddns -D example.com                  # direct mode: check the target itself, not its CNAME
uv run baddns -s example.com                  # silent: JSON results only
uv run baddns -c ./my-signatures example.com  # alternate signature directory
uv run baddns -n 1.1.1.1 example.com          # custom nameservers
```

`--min-confidence` and `--min-severity` filter output. `--disable-mx-gate` runs the email modules even when the domain has no MX records.

### Tests

Tests mock DNS, HTTP and WHOIS; almost nothing touches the network, so a new test usually means a new mock rather than a new fixture.

- `tests/conftest.py` — shared fixtures: `configure_mock_resolver`, `mock_http`, `mock_dispatch_whois`, `cached_suffix_list`, `dnswalk_harness`.
- `tests/helpers.py` — `MockDNSWalk`, `MockWhois`, `MockQueryAnswer`, `DnsWalkHarness`.
- `baddns/mock_blasthttp.py` — `MockBlastHTTP`, `MockResponse`, `MockHeaders`. HTTP is mocked by passing one of these as `http_client`, not by patching a transport.
- `pyfakefs` (the `fs` fixture) fakes the filesystem, which is how signature-loading tests write YAML to a fake `/tmp/signatures`.

Mocks drift from reality. When a test asserts on a third-party error string or response body, check it against the real service before trusting it.
