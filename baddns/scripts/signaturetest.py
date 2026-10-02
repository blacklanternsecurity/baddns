"""Live-test a signature file against the service it describes.

For each word CNAME in the signature:
  - if <random>.<cname> resolves (wildcard platform), request it and run the matcher;
  - otherwise send a Host-header probe: a random unregistered hostname sent to the CNAME's IP,
    which is what the platform sees for a dangling custom domain.
Probes use baddns's own User-Agent, and never example.com (it is on Cloudflare, which changes
Cloudflare-fronted platforms' responses).

Prints JSON: {"signature_pass": bool, "untestable": bool, "match_table": {...}, "error": str|null}
"""

import os
import sys
import json
import string
import random
import asyncio
import subprocess
import types

import yaml
import dns.resolver
from blasthttp import BlastHTTP

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from lib.signature import BadDNSSignature  # noqa: E402
from lib.matcher import Matcher  # noqa: E402
from lib.errors import BadDNSSignatureException  # noqa: E402
from lib.httpmanager import USER_AGENT  # noqa: E402

rand_pool = string.ascii_lowercase


def rand_string(length=12):
    return "".join(random.choice(rand_pool) for _ in range(int(length)))


def resolve_a(name):
    try:
        return [a.to_text() for a in dns.resolver.resolve(name, "A")]
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except Exception:
        return None


def host_header_response(target, scheme):
    """Request a random unregistered hostname from target's IP; return a matcher-compatible response or None."""
    ips = resolve_a(target)
    if not isinstance(ips, list) or not ips:
        return None
    fake = f"zq{rand_string(8)}.zq{rand_string(12)}.com"
    port = 80 if scheme == "http" else 443
    try:
        out = subprocess.run(
            [
                "curl",
                "-sk",
                "-m",
                "10",
                "-A",
                USER_AGENT,
                "-D",
                "-",
                "--resolve",
                f"{fake}:{port}:{ips[0]}",
                f"{scheme}://{fake}/",
            ],
            capture_output=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        return None
    raw = out.stdout.decode(errors="replace")
    head, _, body = raw.partition("\r\n\r\n")
    lines = head.split("\r\n")
    if not lines or not lines[0].startswith("HTTP"):
        return None
    headers = [tuple(h.split(": ", 1)) for h in lines[1:] if ": " in h]
    return types.SimpleNamespace(status=int(lines[0].split()[1]), headers=headers, body=body, text=body)


async def http_matches(client, matcher, host):
    for scheme in ("http", "https"):
        for follow_redirects in (True, False):
            try:
                r = await client.request(
                    f"{scheme}://{host}/",
                    method="GET",
                    headers=[("User-Agent", USER_AGENT)],
                    follow_redirects=follow_redirects,
                    timeout=5,
                    verify_certs=False,
                )
                if matcher.is_match(r):
                    return True
            except Exception:
                pass
    return False


async def process_file(file_path):
    match_table = {}
    with open(file_path, "r") as file:
        sig_yaml = yaml.safe_load(file.read())

    sig = BadDNSSignature()
    try:
        sig.initialize(**sig_yaml)
    except BadDNSSignatureException as e:
        return False, False, {}, f"Failed Signature Validation: [{e}]"

    mode = sig.signature["mode"]
    cnames = [c["value"].lstrip(".") for c in sig.signature["identifiers"]["cnames"] if c["type"] == "word"]

    if mode == "dns_nosoa":
        return True, True, {}, "dns_nosoa signatures can't be live-tested without a real delegation"

    if not cnames:
        return False, True, {}, "No word CNAMEs to test (unscoped or IP-only signature)"

    if mode == "dns_nxdomain":
        for cname in cnames:
            match_table[cname] = resolve_a(f"{rand_string()}.{cname}") == "NXDOMAIN"
        passed = any(match_table.values())
        return passed, False, match_table, None if passed else "No CNAMES gave expected NXDOMAIN response"

    matcher = Matcher(sig.signature)
    client = BlastHTTP()
    untestable = []
    for cname in cnames:
        host = f"{rand_string()}.{cname}"
        if isinstance(resolve_a(host), list) and await http_matches(client, matcher, host):
            match_table[cname] = True
            continue
        # not wildcard, or the wildcard page isn't the dangling state (e.g. custom-domain-only fingerprints)
        responses = [r for r in (host_header_response(cname, s) for s in ("http", "https")) if r is not None]
        if not responses:
            match_table[cname] = "untestable"
            untestable.append(cname)
            continue
        match_table[cname] = any(matcher.is_match(r) for r in responses)

    passed = any(v is True for v in match_table.values())
    all_untestable = len(untestable) == len(cnames)
    error = None
    if not passed:
        error = (
            "No CNAME target could be probed (not wildcard and no A record)"
            if all_untestable
            else "No CNAMES passed random-subdomain or Host-header matcher validation"
        )
    return passed, all_untestable, match_table, error


def main():
    if len(sys.argv) != 2:
        print("Usage: python signaturetest.py <input_file>")
        sys.exit(1)

    signature_pass, untestable, match_table, error = asyncio.run(process_file(sys.argv[1]))
    print(
        json.dumps(
            {"signature_pass": signature_pass, "untestable": untestable, "match_table": match_table, "error": error}
        )
    )


if __name__ == "__main__":
    main()
