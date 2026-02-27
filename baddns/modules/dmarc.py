from baddns.base import BadDNS_base
from baddns.lib.dnsmanager import DNSManager
from baddns.lib.findings import Finding

import logging

log = logging.getLogger(__name__)


class BadDNS_dmarc(BadDNS_base):
    name = "DMARC"
    description = "Check for missing or misconfigured DMARC records"

    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)
        self.dmarc_target = f"_dmarc.{target}"
        self.target_dnsmanager = DNSManager(
            self.dmarc_target, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers
        )
        self.dmarc_tags = None

    @staticmethod
    def parse_dmarc_record(record):
        tags = {}
        parts = record.split(";")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            key, sep, value = part.partition("=")
            if not sep:
                continue
            tags[key.strip().lower()] = value.strip()
        if tags.get("v", "").lower() != "dmarc1":
            return None
        return tags

    async def dispatch(self):
        await self.target_dnsmanager.dispatchDNS(omit_types=["A", "AAAA", "CNAME", "NS", "SOA", "MX", "NSEC"])
        txt_records = self.target_dnsmanager.answers["TXT"]
        if txt_records:
            for record in txt_records:
                tags = self.parse_dmarc_record(record)
                if tags is not None:
                    self.dmarc_tags = tags
                    break
        return True

    def analyze(self):
        findings = []

        if self.dmarc_tags is None:
            findings.append(
                Finding(
                    {
                        "target": self.target,
                        "description": "No DMARC record found - domain has no protection against email spoofing",
                        "confidence": "CONFIRMED",
                        "signature": "N/A",
                        "indicator": "No DMARC record",
                        "trigger": self.dmarc_target,
                        "module": type(self),
                    }
                )
            )
            return findings

        p = self.dmarc_tags.get("p", "").lower()
        if p == "none":
            findings.append(
                Finding(
                    {
                        "target": self.target,
                        "description": "DMARC policy is set to none - spoofed emails will be delivered",
                        "confidence": "POSSIBLE",
                        "signature": "N/A",
                        "indicator": "p=none",
                        "trigger": self.dmarc_target,
                        "module": type(self),
                    }
                )
            )

        sp = self.dmarc_tags.get("sp", "").lower()
        if sp == "none":
            findings.append(
                Finding(
                    {
                        "target": self.target,
                        "description": "DMARC subdomain policy is set to none - subdomains can be spoofed",
                        "confidence": "POSSIBLE",
                        "signature": "N/A",
                        "indicator": "sp=none",
                        "trigger": self.dmarc_target,
                        "module": type(self),
                    }
                )
            )

        pct_raw = self.dmarc_tags.get("pct")
        if pct_raw is not None:
            try:
                pct = int(pct_raw)
                if pct < 100:
                    findings.append(
                        Finding(
                            {
                                "target": self.target,
                                "description": "DMARC policy is only partially applied",
                                "confidence": "POSSIBLE",
                                "signature": "N/A",
                                "indicator": f"pct={pct}",
                                "trigger": self.dmarc_target,
                                "module": type(self),
                            }
                        )
                    )
            except ValueError:
                log.debug(f"Invalid pct value in DMARC record: {pct_raw}")

        if "rua" not in self.dmarc_tags:
            findings.append(
                Finding(
                    {
                        "target": self.target,
                        "description": "No DMARC aggregate reporting (rua) configured",
                        "confidence": "POSSIBLE",
                        "signature": "N/A",
                        "indicator": "No rua tag",
                        "trigger": self.dmarc_target,
                        "module": type(self),
                    }
                )
            )

        return findings
