#!/usr/bin/env python3
"""Rewrite every shipped signature in the canonical on-disk form.

The SignatureBot decides whether to open a PR by comparing a freshly imported signature against the
shipped one byte for byte. Whenever the serialized form changes -- a new identifier shape, a new
field -- every shipped signature stops matching what the importer would now write, and the bot
re-proposes all of them at once. Run this after any such change so the shipped files move with it.

    python3 baddns/scripts/normalize_signatures.py            rewrite drifted signatures
    python3 baddns/scripts/normalize_signatures.py --check    report drift, exit non-zero, write nothing
"""

import os
import sys
import yaml
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from lib.signature import BadDNSSignature  # noqa: E402
from lib.errors import BadDNSSignatureException  # noqa: E402

SIGNATURE_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "signatures")


def canonical_form(path):
    """The canonical serialization of the signature in one file."""
    with open(path) as f:
        candidate = BadDNSSignature()
        candidate.initialize(**yaml.safe_load(f))
    return candidate.canonical_yaml()


def drifted_signatures(signature_dir=SIGNATURE_DIR):
    """Shipped signatures whose file differs from its canonical form, as (filename, canonical)."""
    drifted = []
    for filename in sorted(os.listdir(signature_dir)):
        if not filename.endswith(".yml"):
            continue
        path = os.path.join(signature_dir, filename)
        canonical = canonical_form(path)
        with open(path) as f:
            if f.read() != canonical:
                drifted.append((filename, canonical))
    return drifted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report drift and exit non-zero, write nothing")
    args = parser.parse_args()

    try:
        drifted = drifted_signatures()
    except BadDNSSignatureException as e:
        print(f"A shipped signature does not validate, fix that first: {e}", file=sys.stderr)
        return 2

    if not drifted:
        print("All signatures are in canonical form")
        return 0

    for filename, canonical in drifted:
        if args.check:
            print(f"DRIFT {filename}")
            continue
        with open(os.path.join(SIGNATURE_DIR, filename), "w") as f:
            f.write(canonical)
        print(f"rewrote {filename}")

    if args.check:
        print(
            f"\n{len(drifted)} signature(s) are not in canonical form. The SignatureBot would "
            f"re-propose each one.\nRun: python3 baddns/scripts/normalize_signatures.py",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
