import uuid
import logging

from baddns.base import BadDNS_base
from baddns.lib.dnsmanager import DNSManager
from baddns.lib.httpmanager import HttpManager
from baddns.modules.cname import BadDNS_cname
from baddns.lib.findings import Finding

log = logging.getLogger(__name__)


class BadDNS_wildcard(BadDNS_base):
    name = "WILDCARD"
    description = "Check for wildcard DNS records that could enable domain-wide subdomain takeover"

    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)
        self.target = target
        self.target_dnsmanager = DNSManager(
            target, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers
        )
        self.target_httpmanager = HttpManager(
            self.target, http_client_class=self.http_client_class, skip_redirects=True
        )
        self.cname_findings = None
        self.cname_findings_direct = None
        self.parent_domain = None

    @staticmethod
    def _generate_random_label():
        return f"baddns-{uuid.uuid4().hex[:8]}"

    def _get_parent_domain(self):
        parts = self.target.split(".")
        if len(parts) < 3:
            return None
        return ".".join(parts[1:])

    async def dispatch(self):
        self.cname_findings_direct = []
        self.cname_findings = []

        self.parent_domain = self._get_parent_domain()
        if self.parent_domain is None:
            log.debug(f"Target {self.target} has no suitable parent domain for wildcard check, skipping")
            return False

        random_label = self._generate_random_label()
        probe_target = f"{random_label}.{self.parent_domain}"
        log.debug(f"Probing wildcard with random subdomain: {probe_target}")

        probe_dnsmanager = DNSManager(
            probe_target, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers
        )
        await probe_dnsmanager.dispatchDNS(omit_types=["MX", "NS", "SOA", "TXT", "NSEC"])

        if probe_dnsmanager.answers["NXDOMAIN"]:
            log.debug(f"No wildcard DNS record found for *.{self.parent_domain}")
            return False

        if not probe_dnsmanager.answers["CNAME"]:
            log.debug(f"Wildcard exists for *.{self.parent_domain} but has no CNAME (A/AAAA only), skipping")
            return False

        wildcard_cname = probe_dnsmanager.answers["CNAME"][-1]
        self.infomsg(f"Wildcard CNAME detected: *.{self.parent_domain} -> {wildcard_cname}")

        cname_instance_direct = BadDNS_cname(
            wildcard_cname,
            custom_nameservers=self.custom_nameservers,
            signatures=self.signatures,
            direct_mode=True,
            parent_class="wildcard",
            http_client_class=self.http_client_class,
            dns_client=self.dns_client,
        )
        if await cname_instance_direct.dispatch():
            self.cname_findings_direct.append(
                {
                    "finding": cname_instance_direct.analyze(),
                    "description": f"Wildcard CNAME detected at *.{self.parent_domain}. ALL subdomains of {self.parent_domain} are affected",
                    "trigger": f"*.{self.parent_domain}",
                }
            )
        await cname_instance_direct.cleanup()

        # Use the probe target (not the CNAME target) so the CNAME module
        # discovers the chain naturally and can detect generic dangling CNAMEs
        cname_instance = BadDNS_cname(
            probe_target,
            custom_nameservers=self.custom_nameservers,
            signatures=self.signatures,
            direct_mode=False,
            parent_class="wildcard",
            http_client_class=self.http_client_class,
            dns_client=self.dns_client,
        )
        if await cname_instance.dispatch():
            self.cname_findings.append(
                {
                    "finding": cname_instance.analyze(),
                    "description": f"Wildcard CNAME detected at *.{self.parent_domain}. ALL subdomains of {self.parent_domain} are affected",
                    "trigger": f"*.{self.parent_domain}",
                }
            )
        await cname_instance.cleanup()

        return True

    def _convert_findings(self, finding_sets):
        converted_findings = []
        for finding_set in finding_sets:
            for finding in finding_set["finding"]:
                finding_dict = finding.to_dict()
                log.debug(f"Found finding during wildcard cname check for target: {finding_dict['target']}")
                converted_findings.append(
                    Finding(
                        {
                            "target": self.target,
                            "description": f"{finding_set['description']}. Original Event: [{finding_dict['description']}]",
                            "confidence": finding_dict["confidence"],
                            "severity": "HIGH",
                            "signature": finding_dict["signature"],
                            "indicator": finding_dict["indicator"],
                            "trigger": finding_set["trigger"],
                            "module": type(self),
                        }
                    )
                )
        return converted_findings

    def analyze(self):
        findings = []
        log.debug("in wildcard analyze")
        if self.cname_findings_direct:
            findings.extend(self._convert_findings(self.cname_findings_direct))
        if self.cname_findings:
            findings.extend(self._convert_findings(self.cname_findings))
        return findings

    async def cleanup(self):
        if self.target_httpmanager:
            await self.target_httpmanager.close()
            log.debug("HTTP Manager cleaned up successfully.")
