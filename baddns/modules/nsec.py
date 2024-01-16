from baddns.base import BadDNS_base
from baddns.lib.dnsmanager import DNSManager
from baddns.lib.findings import Finding

import logging

log = logging.getLogger(__name__)


class BadDNS_nsec(BadDNS_base):
    name = "NSEC"
    description = "Enumerate subdomains by NSEC-walking"

    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)
        self.target = target
        self.target_dnsmanager = DNSManager(target, dns_client=self.dns_client)
        self.nsec_chain = []

    async def get_nsec_record(self, domain):
        domain = domain.replace("\\000.", "")
        result = await self.target_dnsmanager.do_resolve(domain, "NSEC")
        if result:
            return result

    async def nsec_walk(self, domain):
        log.debug("in nsec_walk")
        current_domain = domain
        while 1:
            next_domain = await self.get_nsec_record(current_domain)
            if next_domain is None or next_domain[0] in self.nsec_chain:
                break
            log.debug(f"Found additiona NSEC record: {next_domain}")
            if not next_domain[0].startswith("\\"):
                self.nsec_chain.append(next_domain[0])
            current_domain = next_domain[0]

    async def dispatch(self):
        log.debug("in dispatch")
        await self.target_dnsmanager.dispatchDNS(omit_types=["A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT"])
        if self.target_dnsmanager.answers["NSEC"] == None:
            log.debug("No NSEC records found, aborting")
            return False

        self.nsec_chain.append(self.target)
        log.info(f"NSEC Records detected, attempting NSEC walk against domain [{self.target}]")
        await self.nsec_walk(self.target_dnsmanager.answers["NSEC"][0])
        return True

    def analyze(self):
        log.debug("in analyze")
        findings = []

        findings.append(
            Finding(
                {
                    "target": self.target_dnsmanager.target,
                    "description": f"DNSSEC NSEC Zone Walking Enabled for domain: {self.target}",
                    "confidence": "CONFIRMED",
                    "signature": "N/A",
                    "indicator": "NSEC Records",
                    "trigger": self.target,
                    "module": type(self),
                    "data": self.nsec_chain,
                }
            )
        )
        return findings