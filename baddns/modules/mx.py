from baddns.base import BadDNS_base

from baddns.lib.findings import Finding
from baddns.lib.dnsmanager import DNSManager
from baddns.lib.whoismanager import WhoisManager
import logging

log = logging.getLogger(__name__)


class BadDNS_mx(BadDNS_base):
    name = "MX"
    description = "Check for dangling MX records and assess their base domains for availability"

    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)

        self.target_dnsmanager = DNSManager(
            target, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers
        )
        self.mx_whoismanager = {}

    async def dispatch(self):
        await self.target_dnsmanager.dispatchDNS(omit_types=["A", "AAAA", "CNAME", "NS", "SOA", "TXT", "NSEC"])
        if self.target_dnsmanager.answers["MX"] == None:
            log.debug("No MX records found, aborting")
            return False

        for mx_record in self.target_dnsmanager.answers["MX"]:
            log.debug(f"performing WHOIS lookup for [{mx_record}]")
            self.mx_whoismanager[mx_record] = WhoisManager(mx_record)
            await self.mx_whoismanager[mx_record].dispatchWHOIS()
            log.debug(f"WHOIS dispatch [{mx_record}] complete")
        return True

    def analyze(self):
        findings = []
        log.debug("Received the following MX answers:")
        log.debug(self.target_dnsmanager.answers["MX"])

        for whois_domain, whois_data in self.mx_whoismanager.items():
            for whois_finding in whois_data.analyzeWHOIS():
                findings.append(
                    Finding(
                        {
                            "target": self.target_dnsmanager.target,
                            "description": f"MX {whois_finding}",
                            "confidence": "CONFIRMED",
                            "signature": "N/A",
                            "indicator": "Whois Data",
                            "trigger": whois_domain,
                            "module": type(self),
                        }
                    )
                )

        return findings
