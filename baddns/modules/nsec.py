from baddns.base import BadDNS_base
from baddns.lib.dnsmanager import DNSManager
from baddns.lib.findings import Finding

import logging
import tldextract

log = logging.getLogger(__name__)


class BadDNS_nsec(BadDNS_base):
    name = "NSEC"
    description = "Enumerate subdomains by NSEC-walking"

    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)
        self.target = target
        self.target_dnsmanager = DNSManager(
            target, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers
        )
        self.nsec_chain = []

    async def get_nsec_record(self, domain):
        result = await self.target_dnsmanager.do_resolve(domain, "NSEC")
        if result:
            return result[0].replace("\\000.", "")

    async def nsec_walk(self, domain):
        log.debug("in nsec_walk")
        current_domain = domain
        while 1:
            next_domain = await self.get_nsec_record(current_domain)

            # NSEC wildcard protection
            if current_domain == next_domain and len(self.nsec_chain) == 1:
                return False

            if next_domain is None or next_domain in self.nsec_chain:
                break
            log.debug(f"Found additional NSEC record: {next_domain}")
            if not next_domain.startswith("\\"):
                self.nsec_chain.append(next_domain)
            current_domain = next_domain
        return True

    async def dispatch(self):
        log.debug("in dispatch")
        target_base_domain = tldextract.extract(self.target).registered_domain
        await self.target_dnsmanager.dispatchDNS(omit_types=["A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT"])
        if self.target_dnsmanager.answers["NSEC"] == None:
            log.debug("No NSEC records found, aborting")
            return False

        self.nsec_chain.append(self.target)
        nsec_walk = await self.nsec_walk(self.target)
        if nsec_walk:
            self.infomsg(f"NSEC Records detected, attempting NSEC walk against domain [{self.target}]")
            self.nsec_chain.remove(self.target)
            nonmatching_results = len(
                [host for host in self.nsec_chain if not host.endswith(f".{target_base_domain}")]
            )
            if len(self.nsec_chain) == nonmatching_results == 1:
                log.debug(
                    f"Aborting because NSEC chain contained only 1 result [{self.nsec_chain[0]}] which did not match the base domain of the target"
                )
                return False
            return True
        return False

    def analyze(self):
        log.debug("in analyze")
        findings = []

        findings.append(
            Finding(
                {
                    "target": self.target_dnsmanager.target,
                    "description": f"DNSSEC NSEC Zone Walking Enabled for domain: [{self.target}]",
                    "confidence": "CONFIRMED",
                    "signature": "N/A",
                    "indicator": "NSEC Records",
                    "trigger": self.target,
                    "module": type(self),
                    "found_domains": self.nsec_chain,
                }
            )
        )
        return findings
