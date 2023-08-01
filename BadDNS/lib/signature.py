from lib.errors import BadDNSSignatureException


class BadDNSSignature:
    validModes = ["http", "dns_nxdomain", "dns_nosoa"]
    validSources = ["dnsreaper", "canitakeoverxyz", "nucleitemplates", "self"]

    def __init__(self):
        self.signature = {
            "service_name": None,
            "source": None,
            "identifiers": {"cnames": [], "ips": [], "nameservers": []},
            "mode": None,
            "matcher_rule": {},
        }

    def initialize(self, **kwargs):
        self.signature["mode"] = kwargs.get("mode", None)
        self.signature["source"] = kwargs.get("source", None)
        self.signature["service_name"] = kwargs.get("service_name", None)
        identifiers = kwargs.get("identifiers", {})
        self.signature["identifiers"] = {}
        self.signature["identifiers"]["cnames"] = identifiers.get("cnames", [])
        self.signature["identifiers"]["ips"] = identifiers.get("ips", [])
        self.signature["identifiers"]["nameservers"] = identifiers.get("nameservers", [])
        self.signature["matcher_rule"] = kwargs.get("matcher_rule", None)

        if not self.signature["mode"]:
            raise BadDNSSignatureException(f"mode is a required attribute")

        if self.signature["mode"] not in self.validModes:
            raise BadDNSSignatureException(f"Supplied mode [{self.signature.mode}] in not a valid mode")

        if not self.signature["source"]:
            raise BadDNSSignatureException(f"source is a required attribute")

        if self.signature["source"] not in self.validSources:
            raise BadDNSSignatureException(f"Supplied mode [{self.signature['source']}] is not a valid mode")

        if not self.signature["service_name"]:
            raise BadDNSSignatureException(f"service_name is a required attribute")

        if self.signature["mode"] == "http":
            if not self.signature["matcher_rule"]:
                raise BadDNSSignatureException(f"http mode requires a matcher_rule entry")

        if self.signature["mode"].startswith("dns"):
            if self.signature["matcher_rule"]:
                raise BadDNSSignatureException(f"In dns modes, matcher_rule should not be set")
            if (
                len(self.signature["identifiers"]["cnames"]) == 0
                and len(self.signature["identifiers"]["ips"]) == 0
                and len(self.signature["identifiers"]["nameservers"]) == 0
            ):
                raise BadDNSSignatureException(
                    f"All DNS signatures require an identifier (cnames, ips, or nameservers)"
                )

        if self.signature["mode"] == "dns_nosoa":
            if len(self.signature["identifiers"]["nameservers"]) == 0:
                raise BadDNSSignatureException(f"In dns_nosoa mode, nameservers are required")

    def output(self):
        return self.signature
