import re
import yaml
import logging

from .errors import BadDNSSignatureException
from .findings import CONFIDENCE_LEVELS

log = logging.getLogger(__name__)


class BadDNSSignature:
    validModes = ["http", "dns_nxdomain", "dns_nosoa"]
    validSources = ["dnsreaper", "nucleitemplates", "self"]
    validIdentifierTypes = ["word", "regex"]
    validMatcherTypes = ["word", "regex", "status", "tls_error"]
    validMatcherParts = ["body", "header"]
    validConditions = ["and", "or"]

    def __init__(self):
        self.signature = {
            "service_name": None,
            "source": None,
            "identifiers": {"cnames": [], "not_cnames": [], "ips": [], "nameservers": []},
            "mode": None,
            "matcher_rule": {},
            "negative_signature": False,
        }

    def initialize(self, **kwargs):
        self.signature["mode"] = kwargs.get("mode", None)
        self.signature["source"] = kwargs.get("source", None)
        self.signature["service_name"] = kwargs.get("service_name", None)
        identifiers = kwargs.get("identifiers", {})
        self.signature["identifiers"] = {
            key: self._normalize_identifiers(key, identifiers.get(key, []))
            for key in ("cnames", "not_cnames", "ips", "nameservers")
        }
        self.signature["matcher_rule"] = kwargs.get("matcher_rule", None)
        self.signature["negative_signature"] = kwargs.get("negative_signature", False)
        # Optional per-signature confidence for findings it produces (default is the module's own level).
        # Only stored when set, so existing signature files and importer output are unchanged.
        confidence = kwargs.get("confidence", None)
        if confidence is not None:
            if confidence not in CONFIDENCE_LEVELS:
                raise BadDNSSignatureException(
                    f"Invalid confidence [{confidence}] (must be one of: {', '.join(CONFIDENCE_LEVELS)})"
                )
            self.signature["confidence"] = confidence

        if not self.signature["mode"]:
            raise BadDNSSignatureException(f"mode is a required attribute")

        if self.signature["mode"] not in self.validModes:
            raise BadDNSSignatureException(f"Supplied mode [{self.signature['mode']}] is not a valid mode")

        if not self.signature["source"]:
            raise BadDNSSignatureException(f"source is a required attribute")

        if self.signature["source"] not in self.validSources:
            raise BadDNSSignatureException(f"Supplied mode [{self.signature['source']}] is not a valid mode")

        if not self.signature["service_name"]:
            raise BadDNSSignatureException(f"service_name is a required attribute")

        if self.signature["mode"] == "http":
            if not self.signature["matcher_rule"]:
                raise BadDNSSignatureException(f"http mode requires a matcher_rule entry")
            self._validate_matchers(self.signature["matcher_rule"])

        if self.signature["mode"].startswith("dns"):
            if self.signature["matcher_rule"]:
                raise BadDNSSignatureException(f"In dns modes, matcher_rule should not be set")

        if self.signature["mode"] == "dns_nosoa":
            if len(self.signature["identifiers"]["nameservers"]) == 0:
                raise BadDNSSignatureException(f"In dns_nosoa mode, nameservers are required")

    def _normalize_identifiers(self, key, identifiers):
        """Bring one identifier list into the {type, value} form the modules match against.

        Bare strings are accepted as ``word`` identifiers: dns_nosoa signatures have always written
        nameservers that way, and the dnsReaper importer writes IPs that way. ``regex`` identifiers are
        compiled here so a bad pattern fails at load instead of silently never matching at scan time.
        """
        normalized = []
        for identifier in identifiers:
            if isinstance(identifier, str):
                identifier = {"type": "word", "value": identifier}
            if not isinstance(identifier, dict):
                raise BadDNSSignatureException(
                    f"Identifier in [{key}] must be a string or a mapping, got [{identifier!r}]"
                )
            identifier_type = identifier.get("type", "word")
            value = identifier.get("value")
            if identifier_type not in self.validIdentifierTypes:
                raise BadDNSSignatureException(
                    f"Unsupported identifier type [{identifier_type}] in [{key}] "
                    f"(supported: {', '.join(self.validIdentifierTypes)})"
                )
            if not isinstance(value, str) or not value:
                raise BadDNSSignatureException(f"Identifier in [{key}] requires a non-empty string value")
            if identifier_type == "regex":
                # An IP identifier is exact membership against resolved addresses, so a pattern there
                # would never match. Reject it rather than let it fail silently.
                if key == "ips":
                    raise BadDNSSignatureException("regex identifiers are not supported for [ips]")
                try:
                    re.compile(value)
                except re.error as e:
                    raise BadDNSSignatureException(f"Invalid identifier regex [{value}] in [{key}]: {e}")
            normalized.append({"type": identifier_type, "value": value})
        return normalized

    def _validate_matchers(self, matcher_rule):
        """Reject matcher constructs the Matcher can't evaluate, so a signature never silently loses logic."""
        if matcher_rule.get("matchers-condition", "and") not in self.validConditions:
            raise BadDNSSignatureException(f"Invalid matchers-condition [{matcher_rule.get('matchers-condition')}]")
        matchers = matcher_rule.get("matchers") or []
        if not matchers:
            raise BadDNSSignatureException("matcher_rule must contain at least one matcher")
        for matcher in matchers:
            matcher_type = matcher.get("type")
            if matcher_type not in self.validMatcherTypes:
                raise BadDNSSignatureException(
                    f"Unsupported matcher type [{matcher_type}] (supported: {', '.join(self.validMatcherTypes)})"
                )
            if matcher_type == "status":
                if not isinstance(matcher.get("status"), int):
                    raise BadDNSSignatureException(
                        f"status matcher requires an integer status, got [{matcher.get('status')}]"
                    )
                continue
            if matcher_type == "tls_error":
                if not matcher.get("words"):
                    raise BadDNSSignatureException("tls_error matcher requires a non-empty [words] list")
                if matcher.get("condition", "and") not in self.validConditions:
                    raise BadDNSSignatureException(f"Invalid matcher condition [{matcher.get('condition')}]")
                continue
            part = matcher.get("part", "body")
            if part not in self.validMatcherParts:
                raise BadDNSSignatureException(
                    f"Unsupported matcher part [{part}] (supported: {', '.join(self.validMatcherParts)})"
                )
            if matcher.get("condition", "and") not in self.validConditions:
                raise BadDNSSignatureException(f"Invalid matcher condition [{matcher.get('condition')}]")
            key = "words" if matcher_type == "word" else "regex"
            if not matcher.get(key):
                raise BadDNSSignatureException(f"{matcher_type} matcher requires a non-empty [{key}] list")
            if matcher_type == "regex":
                for pattern in matcher["regex"]:
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        raise BadDNSSignatureException(f"Invalid regex [{pattern}]: {e}")

    def output(self):
        return self.signature

    def canonical_yaml(self):
        """The canonical on-disk form of this signature.

        Signature files are compared byte for byte -- the SignatureBot decides whether to open a PR
        by diffing a freshly imported signature against the shipped one -- so there is exactly one
        serialization, and everything that writes a signature file goes through here. A shipped file
        that drifts out of this form makes the bot re-propose every signature at once.
        """
        output = dict(self.signature)
        if not output.get("negative_signature"):
            output.pop("negative_signature", None)
        return yaml.dump(output)

    def summarize_matcher_rule(self):
        summary = []

        if "matchers" in self.signature["matcher_rule"].keys():
            for matcher in self.signature["matcher_rule"]["matchers"]:
                if matcher["type"] == "word":
                    words = ", ".join(matcher["words"])
                    condition = matcher.get("condition", "")
                    part = matcher.get("part", "")
                    summary.append(f"[Words: {words} | Condition: {condition} | Part: {part}]")
                elif matcher["type"] == "tls_error":
                    summary.append(f"[TLS handshake error: {', '.join(matcher['words'])}]")
            return ", ".join(summary) + f" Matchers-Condition: {self.signature['matcher_rule']['matchers-condition']}"
        else:
            return "No matchers in signature"


def identifier_matches(identifier, name, mode="substring"):
    """True if one identifier matches a DNS name.

    ``regex`` identifiers are always ``re.search`` against the whole name, so a pattern can anchor
    itself with ``^``/``$`` and express shapes a substring can't. ``word`` identifiers keep whatever
    comparison the call site has always used: ``suffix`` on the NXDOMAIN paths, ``substring`` on the
    HTTP and nameserver paths.
    """
    value = identifier["value"]
    if identifier["type"] == "regex":
        return re.search(value, name) is not None
    if mode == "suffix":
        return name.endswith(value)
    return value in name


def any_identifier_matches(identifiers, name, mode="substring"):
    return any(identifier_matches(identifier, name, mode) for identifier in identifiers)
