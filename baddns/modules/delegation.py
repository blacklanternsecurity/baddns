import logging

from baddns.base import BadDNS_base
from baddns.lib.dnsmanager import DNSManager
from baddns.lib.findings import Finding
from baddns.modules.cname import BadDNS_cname

log = logging.getLogger(__name__)

# Labels commonly delegated to third parties by CNAME. These names are rarely enumerated,
# so dangling delegations here are easy to miss.
ACME_LABEL = "_acme-challenge"
DMARC_LABEL = "_dmarc"
DKIM_SELECTORS = [
    "default",
    "dkim",
    "google",
    "k1",
    "k2",
    "k3",
    "mail",
    "s1",
    "s2",
    "selector1",
    "selector2",
    "sig1",
    "smtp",
    "zendesk1",
    "zendesk2",
]

LABEL_IMPACT = {
    "acme": "certificate issuance for the domain may be possible",
    "dmarc": "the DMARC policy for the domain may be controllable",
    "dkim": "email signed as the domain may pass DKIM",
}


class BadDNS_delegation(BadDNS_base):
    name = "DELEGATION"
    description = "Check _acme-challenge, _dmarc and common DKIM selector CNAMEs for dangling delegations"

    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)
        self.target = target
        self.target_dnsmanager = DNSManager(
            target, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers
        )
        self.label_findings = []

    def _labels(self):
        yield "acme", f"{ACME_LABEL}.{self.target}"
        yield "dmarc", f"{DMARC_LABEL}.{self.target}"
        for selector in DKIM_SELECTORS:
            yield "dkim", f"{selector}._domainkey.{self.target}"

    async def _dispatch(self):
        for kind, host in self._labels():
            cname_instance = BadDNS_cname(
                host,
                custom_nameservers=self.custom_nameservers,
                signatures=self.signatures,
                direct_mode=False,
                parent_class="delegation",
                allow_delegation_labels=True,
                http_client=self.http_client,
                dns_client=self.dns_client,
            )
            # dispatch() returns False when the label has no CNAME, which is the common case
            if await cname_instance.dispatch():
                results = cname_instance.analyze()
                if results:
                    self.label_findings.append((kind, host, results))
            await cname_instance.cleanup()
        return bool(self.label_findings)

    def analyze(self):
        findings = []
        for kind, host, results in self.label_findings:
            for finding in results:
                finding_dict = finding.to_dict()
                # A CNAME to a name that simply doesn't exist is normal here (e.g. Microsoft 365 publishes only
                # the active DKIM selector of a pair). Keep only claimable outcomes: an unregistered/expired
                # target domain, or a known-vulnerable service signature.
                if finding_dict["signature"] == "GENERIC":
                    continue
                findings.append(
                    Finding(
                        {
                            "target": self.target,
                            "description": (
                                f"Dangling {kind.upper()} delegation [{host}]: {LABEL_IMPACT[kind]}. "
                                f"Original Event: [{finding_dict['description']}]"
                            ),
                            "confidence": finding_dict["confidence"],
                            "severity": "HIGH",
                            "signature": finding_dict["signature"],
                            "indicator": finding_dict["indicator"],
                            "trigger": host,
                            "module": type(self),
                        }
                    )
                )
        return findings
