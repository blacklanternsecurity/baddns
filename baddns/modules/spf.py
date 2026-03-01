from baddns.base import BadDNS_base
from baddns.lib.dnsmanager import DNSManager
from baddns.lib.whoismanager import WhoisManager
from baddns.lib.findings import Finding

import logging
import tldextract

log = logging.getLogger(__name__)


class BadDNS_spf(BadDNS_base):
    name = "SPF"
    description = "Check for missing or misconfigured SPF records and hijackable include/redirect domains"

    # Mechanisms that consume a DNS lookup per RFC 7208 Section 4.6.4
    _dns_lookup_mechanisms = {"include", "a", "mx", "ptr", "exists", "redirect"}

    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)
        self.target_dnsmanager = DNSManager(
            target, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers
        )
        self.spf_records = []
        self.parsed_spf = None
        self.spf_whoismanagers = {}
        self.is_subdomain = False
        self.org_spf_records = []
        self.org_parsed_spf = None

    @staticmethod
    def parse_spf_record(record):
        """Parse an SPF TXT record into a structured dict.

        Returns a dict with keys: all_qualifier, includes, redirect, dns_lookup_count, mechanisms
        Returns None if the record is not a valid SPF record.
        """
        record = record.strip()
        parts = record.split()
        if not parts or parts[0].lower() != "v=spf1":
            return None

        result = {
            "all_qualifier": None,
            "includes": [],
            "redirect": None,
            "dns_lookup_count": 0,
            "mechanisms": parts[1:],
        }

        for token in parts[1:]:
            token_lower = token.lower()

            # Handle the 'all' mechanism
            if token_lower == "all" or token_lower.endswith("all") and len(token_lower) <= 4:
                qualifier = "+"  # default qualifier
                if token_lower == "all":
                    qualifier = "+"
                elif token[0] in "+-~?":
                    qualifier = token[0]
                result["all_qualifier"] = qualifier
                continue

            # Determine qualifier prefix
            qualifier = "+"
            mechanism = token
            if token[0] in "+-~?":
                qualifier = token[0]
                mechanism = token[1:]

            mechanism_lower = mechanism.lower()

            # Handle redirect modifier (uses = not :)
            if mechanism_lower.startswith("redirect="):
                domain = mechanism[9:]  # len("redirect=") == 9
                result["redirect"] = domain
                result["dns_lookup_count"] += 1
                continue

            # Handle include mechanism
            if mechanism_lower.startswith("include:"):
                domain = mechanism[8:]  # len("include:") == 8
                result["includes"].append(domain)
                result["dns_lookup_count"] += 1
                continue

            # Count other DNS-lookup-consuming mechanisms
            mech_name = mechanism_lower.split(":")[0].split("/")[0]
            if mech_name in ("a", "mx", "ptr", "exists"):
                result["dns_lookup_count"] += 1

        return result

    async def _dispatch(self):
        await self.target_dnsmanager.dispatchDNS(omit_types=["A", "AAAA", "CNAME", "NS", "SOA", "MX", "NSEC"])
        txt_records = self.target_dnsmanager.answers["TXT"]

        if txt_records:
            for record in txt_records:
                parsed = self.parse_spf_record(record)
                if parsed is not None:
                    self.spf_records.append(record)

        # If no SPF record found and target is a subdomain, fall back to organizational domain
        if not self.spf_records:
            registered_domain = tldextract.extract(self.target).registered_domain
            if registered_domain and registered_domain != self.target:
                self.is_subdomain = True
                log.debug(f"No SPF at {self.target}, falling back to {registered_domain}")
                org_dnsmanager = DNSManager(
                    registered_domain, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers
                )
                await org_dnsmanager.dispatchDNS(omit_types=["A", "AAAA", "CNAME", "NS", "SOA", "MX", "NSEC"])
                org_txt = org_dnsmanager.answers["TXT"]
                if org_txt:
                    for record in org_txt:
                        parsed = self.parse_spf_record(record)
                        if parsed is not None:
                            self.org_spf_records.append(record)
                if self.org_spf_records:
                    self.org_parsed_spf = self.parse_spf_record(self.org_spf_records[0])

        # Parse the first SPF record for analysis
        if self.spf_records:
            self.parsed_spf = self.parse_spf_record(self.spf_records[0])

        # Determine which parsed SPF to use for WHOIS checks
        effective_spf = self.parsed_spf or self.org_parsed_spf

        # Run WHOIS on include and redirect domains
        if effective_spf:
            domains_to_check = list(effective_spf["includes"])
            if effective_spf["redirect"]:
                domains_to_check.append(effective_spf["redirect"])

            for domain in domains_to_check:
                if not domain:
                    continue
                log.debug(f"performing WHOIS lookup for SPF domain [{domain}]")
                self.spf_whoismanagers[domain] = WhoisManager(domain)
                await self.spf_whoismanagers[domain].dispatchWHOIS()
                log.debug(f"WHOIS dispatch [{domain}] complete")

        return True

    def _analyze_spf(self, parsed_spf, spf_records):
        """Analyze a parsed SPF record for policy issues. Returns list of Findings."""
        findings = []

        # Check: Multiple SPF records
        if len(spf_records) > 1:
            findings.append(
                Finding(
                    {
                        "target": self.target,
                        "description": "Multiple SPF records found - causes permanent error per RFC 7208, breaks SPF entirely",
                        "confidence": "CONFIRMED",
                        "severity": "INFORMATIONAL",
                        "signature": "N/A",
                        "indicator": f"Multiple SPF records ({len(spf_records)})",
                        "trigger": self.target,
                        "module": type(self),
                    }
                )
            )

        # Check: +all (pass all)
        if parsed_spf["all_qualifier"] == "+":
            findings.append(
                Finding(
                    {
                        "target": self.target,
                        "description": "SPF record uses +all - explicitly authorizes any server to send email",
                        "confidence": "CONFIRMED",
                        "severity": "INFORMATIONAL",
                        "signature": "N/A",
                        "indicator": "+all",
                        "trigger": self.target,
                        "module": type(self),
                    }
                )
            )

        # Check: ?all (neutral)
        elif parsed_spf["all_qualifier"] == "?":
            findings.append(
                Finding(
                    {
                        "target": self.target,
                        "description": "SPF record uses ?all - provides no protection against unauthorized senders",
                        "confidence": "CONFIRMED",
                        "severity": "INFORMATIONAL",
                        "signature": "N/A",
                        "indicator": "?all",
                        "trigger": self.target,
                        "module": type(self),
                    }
                )
            )

        # Check: DNS lookup count exceeds 10
        if parsed_spf["dns_lookup_count"] > 10:
            findings.append(
                Finding(
                    {
                        "target": self.target,
                        "description": "SPF record exceeds 10 DNS lookup limit - causes permanent error per RFC 7208",
                        "confidence": "MODERATE",
                        "severity": "INFORMATIONAL",
                        "signature": "N/A",
                        "indicator": f"DNS lookup count: {parsed_spf['dns_lookup_count']}",
                        "trigger": self.target,
                        "module": type(self),
                    }
                )
            )

        return findings

    def analyze(self):
        findings = []

        # Check: No SPF record
        if not self.spf_records:
            # Subdomain with no direct SPF — check if org domain covers it
            if self.is_subdomain and self.org_parsed_spf is not None:
                # Org domain has SPF — analyze it for policy issues (they propagate)
                findings.extend(self._analyze_spf(self.org_parsed_spf, self.org_spf_records))
                # Don't report "No SPF record" — org domain covers subdomains
            else:
                # No SPF anywhere
                findings.append(
                    Finding(
                        {
                            "target": self.target,
                            "description": "No SPF record found - domain has no SPF protection against email spoofing",
                            "confidence": "CONFIRMED",
                            "severity": "INFORMATIONAL",
                            "signature": "N/A",
                            "indicator": "No SPF record",
                            "trigger": self.target,
                            "module": type(self),
                        }
                    )
                )
        else:
            # Target has its own SPF record — analyze it directly
            findings.extend(self._analyze_spf(self.parsed_spf, self.spf_records))

        # Takeover checks: WHOIS on include/redirect domains
        effective_spf = self.parsed_spf or self.org_parsed_spf
        for whois_domain, whois_data in self.spf_whoismanagers.items():
            for whois_finding in whois_data.analyzeWHOIS():
                # Determine if this is an include or redirect domain
                mechanism_type = "include"
                if effective_spf and effective_spf["redirect"] == whois_domain:
                    mechanism_type = "redirect"
                findings.append(
                    Finding(
                        {
                            "target": self.target,
                            "description": f"SPF {mechanism_type} {whois_finding}",
                            "confidence": "CONFIRMED",
                            "severity": "MEDIUM",
                            "signature": "N/A",
                            "indicator": "Whois Data",
                            "trigger": whois_domain,
                            "module": type(self),
                        }
                    )
                )

        return findings
