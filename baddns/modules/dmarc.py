from baddns.base import BadDNS_base
from baddns.lib.dnsmanager import DNSManager
from baddns.lib.findings import Finding

import logging
import tldextract

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
        self.org_dmarc_tags = None
        self.is_subdomain = False

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

    async def _dispatch(self):
        # Step 1: Check _dmarc.<target> (RFC 7489 Section 6.6.3)
        await self.target_dnsmanager.dispatchDNS(omit_types=["A", "AAAA", "CNAME", "NS", "SOA", "MX", "NSEC"])
        txt_records = self.target_dnsmanager.answers["TXT"]
        if txt_records:
            for record in txt_records:
                tags = self.parse_dmarc_record(record)
                if tags is not None:
                    self.dmarc_tags = tags
                    break

        # Step 2: If no record found and target is a subdomain, fall back to organizational domain
        if self.dmarc_tags is None:
            registered_domain = tldextract.extract(self.target).registered_domain
            if registered_domain and registered_domain != self.target:
                self.is_subdomain = True
                org_dmarc_target = f"_dmarc.{registered_domain}"
                log.debug(f"No DMARC at {self.dmarc_target}, falling back to {org_dmarc_target}")
                org_dnsmanager = DNSManager(
                    org_dmarc_target, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers
                )
                await org_dnsmanager.dispatchDNS(omit_types=["A", "AAAA", "CNAME", "NS", "SOA", "MX", "NSEC"])
                org_txt = org_dnsmanager.answers["TXT"]
                if org_txt:
                    for record in org_txt:
                        tags = self.parse_dmarc_record(record)
                        if tags is not None:
                            self.org_dmarc_tags = tags
                            break
        return True

    def _effective_subdomain_policy(self, org_tags):
        """Get the effective policy for a subdomain from the org domain's DMARC record.

        Per RFC 7489: if sp is present, use it; otherwise subdomains inherit p.
        """
        return org_tags.get("sp", org_tags.get("p", "")).lower()

    def analyze(self):
        findings = []

        if self.dmarc_tags is None:
            # Subdomain with no direct DMARC record — check if org domain covers it
            if self.is_subdomain and self.org_dmarc_tags is not None:
                effective_policy = self._effective_subdomain_policy(self.org_dmarc_tags)
                if effective_policy == "none":
                    findings.append(
                        Finding(
                            {
                                "target": self.target,
                                "description": "Subdomain inherits a DMARC policy of none from organizational domain"
                                " - spoofed emails will be delivered",
                                "confidence": "MODERATE",
                                "severity": "INFORMATIONAL",
                                "signature": "N/A",
                                "indicator": f"Inherited policy: {effective_policy}",
                                "trigger": self.dmarc_target,
                                "module": type(self),
                            }
                        )
                    )

                pct_raw = self.org_dmarc_tags.get("pct")
                if pct_raw is not None:
                    try:
                        pct = int(pct_raw)
                        if pct < 100:
                            findings.append(
                                Finding(
                                    {
                                        "target": self.target,
                                        "description": "Inherited DMARC policy is only partially applied",
                                        "confidence": "MODERATE",
                                        "severity": "INFORMATIONAL",
                                        "signature": "N/A",
                                        "indicator": f"pct={pct}",
                                        "trigger": self.dmarc_target,
                                        "module": type(self),
                                    }
                                )
                            )
                    except ValueError:
                        log.debug(f"Invalid pct value in org DMARC record: {pct_raw}")

                # Subdomain is covered by org domain — don't report "no DMARC"
                return findings

            # No DMARC anywhere
            findings.append(
                Finding(
                    {
                        "target": self.target,
                        "description": "No DMARC record found - domain has no protection against email spoofing",
                        "confidence": "CONFIRMED",
                        "severity": "INFORMATIONAL",
                        "signature": "N/A",
                        "indicator": "No DMARC record",
                        "trigger": self.dmarc_target,
                        "module": type(self),
                    }
                )
            )
            return findings

        # Target has its own DMARC record — analyze it directly
        p = self.dmarc_tags.get("p", "").lower()
        if p == "none":
            findings.append(
                Finding(
                    {
                        "target": self.target,
                        "description": "DMARC policy is set to none - spoofed emails will be delivered",
                        "confidence": "MODERATE",
                        "severity": "INFORMATIONAL",
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
                        "confidence": "MODERATE",
                        "severity": "INFORMATIONAL",
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
                                "confidence": "MODERATE",
                                "severity": "INFORMATIONAL",
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
                        "confidence": "MODERATE",
                        "severity": "INFORMATIONAL",
                        "signature": "N/A",
                        "indicator": "No rua tag",
                        "trigger": self.dmarc_target,
                        "module": type(self),
                    }
                )
            )

        return findings
