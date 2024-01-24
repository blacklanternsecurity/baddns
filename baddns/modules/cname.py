import tldextract

from baddns.base import BadDNS_base

from baddns.lib.dnsmanager import DNSManager
from baddns.lib.httpmanager import HttpManager
from baddns.lib.whoismanager import WhoisManager
from baddns.lib.matcher import Matcher
from baddns.lib.findings import Finding

import logging

log = logging.getLogger(__name__)


class BadDNS_cname(BadDNS_base):
    name = "CNAME"
    description = "Check for dangling CNAME records and interrogate them for subdomain takeover opportunities"

    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)

        self.direct_mode = kwargs.get("direct_mode", False)
        self.target_dnsmanager = DNSManager(
            target, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers
        )
        self.target_httpmanager = None
        self.cname_dnsmanager = None
        self.cname_whoismanager = None

    async def dispatch(self):
        await self.target_dnsmanager.dispatchDNS()
        if self.direct_mode == False:
            if self.target_dnsmanager.answers["CNAME"] != None:
                self.infomsg(
                    f"Found CNAME(S) [{' -> '.join([self.target_dnsmanager.target] + self.target_dnsmanager.answers['CNAME'])}]"
                )
                self.subject = self.target_dnsmanager.answers["CNAME"][-1]
            else:
                if self.parent_class == "self":
                    self.infomsg("No CNAME Found :/")
                return False
        else:
            log.debug("Direct mode enabled. Target will be checked for takeover instead of target's CNAME")
            self.subject = self.target
        self.cname_dnsmanager = DNSManager(self.subject, dns_client=self.dns_client)
        await self.cname_dnsmanager.dispatchDNS(omit_types=["CNAME", "NSEC"])

        # if the domain resolves, we can try for HTTP connections
        if not self.cname_dnsmanager.answers["NXDOMAIN"]:
            log.debug("CNAME resolved correctly, proceeding with HTTP dispatch")
            self.target_httpmanager = HttpManager(self.target, http_client_class=self.http_client_class)
            await self.target_httpmanager.dispatchHttp()
            log.debug("HTTP dispatch complete")
        # if the cname doesn't resolve, we still need to see if the base domain is unregistered
        # even if it is registered, we still use whois to check for expired domains
        log.debug("performing WHOIS lookup")

        self.cname_whoismanager = WhoisManager(self.subject)
        await self.cname_whoismanager.dispatchWHOIS()
        log.debug("WHOIS dispatch complete")
        return True

    def analyze(self):
        findings = []
        if self.direct_mode == True:
            trigger = ["self"]
        else:
            trigger = self.target_dnsmanager.answers["CNAME"]
        if self.cname_dnsmanager.answers["NXDOMAIN"]:
            signature_match = False
            indicator = None

            self.infomsg(f"Got NXDOMAIN for CNAME {self.cname_dnsmanager.target}. Checking against signatures...")
            for sig in self.signatures:
                if sig.signature["mode"] == "dns_nxdomain":
                    log.debug(f"Trying signature {sig.signature['service_name']}")
                    sig_cnames = [c["value"] for c in sig.signature["identifiers"]["cnames"]]
                    for sig_cname in sig_cnames:
                        log.debug(f"Checking CNAME {self.cname_dnsmanager.target} against {sig_cname}")
                        if self.cname_dnsmanager.target.endswith(sig_cname):
                            signature_match = True
                            log.debug(f"CNAME {self.cname_dnsmanager.target} vulnerable ({sig_cname})")
                            indicator = sig_cname
                            findings.append(
                                Finding(
                                    {
                                        "target": self.target_dnsmanager.target,
                                        "description": f"Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)",
                                        "confidence": "PROBABLE",
                                        "signature": sig.signature["service_name"],
                                        "indicator": indicator,
                                        "trigger": trigger,
                                        "module": type(self),
                                    }
                                )
                            )
                            break
            if (
                signature_match == False
                and trigger[-1] != "self"
                and tldextract.extract(trigger[-1]).registered_domain
                != tldextract.extract(self.target_dnsmanager.target).registered_domain
            ):
                findings.append(
                    Finding(
                        {
                            "target": self.target_dnsmanager.target,
                            "description": f"Dangling CNAME, possible subdomain takeover (NXDOMAIN technique)",
                            "confidence": "POSSIBLE",
                            "signature": "GENERIC",
                            "indicator": "Generic Dangling CNAME",
                            "trigger": trigger,
                            "module": type(self),
                        }
                    )
                )
            else:
                log.debug(
                    f"Not reporting generic cname for trigger [{trigger}] from domain [{self.target_dnsmanager.target}]"
                )

        else:
            log.debug("Starting HTTP analysis")

            http_results = [
                self.target_httpmanager.http_allowredirects_results,
                self.target_httpmanager.http_denyredirects_results,
                self.target_httpmanager.https_allowredirects_results,
                self.target_httpmanager.https_denyredirects_results,
            ]

            for sig in self.signatures:
                if sig.signature["mode"] == "http":
                    log.debug(f"Trying signature {sig.signature['service_name']}")
                    if len(sig.signature["identifiers"]["cnames"]) > 0:
                        log.debug(
                            f"Signature contains cnames [{sig.signature['identifiers']['cnames']}], checking them"
                        )
                        if not any(
                            cname_dict["value"] in self.subject
                            for cname_dict in sig.signature["identifiers"]["cnames"]
                        ):
                            log.debug(f"no match for {sig.signature['identifiers']['cnames']} for in {self.subject}")
                            continue
                        log.debug("passed CNAME check")

                    if len(sig.signature["identifiers"]["ips"]) > 0:
                        log.debug(f"Signature contains ips [{sig.signature['identifiers']['ips']}], checking them")
                        if not any(
                            ip_signature in self.cname_dnsmanager.ips
                            for ip_signature in sig.signature["identifiers"]["ips"]
                        ):
                            log.debug(
                                f"no match for {sig.signature['identifiers']['ips']} for in {self.cname_dnsmanager.ips}"
                            )
                            continue
                        log.debug("passed IPS")

                    m = Matcher(sig.signature)
                    log.debug("Checking for HTTP matches")
                    if any(m.is_match(hr) for hr in http_results if hr is not None):
                        log.debug(f"CNAME {self.cname_dnsmanager.target} Vulnerable")
                        log.debug(f"With matcher_rule {sig.signature['matcher_rule']}")
                        findings.append(
                            Finding(
                                {
                                    "target": self.target_dnsmanager.target,
                                    "description": f"Dangling CNAME, probable subdomain takeover (HTTP String Match)",
                                    "confidence": "PROBABLE",
                                    "signature": sig.signature["service_name"],
                                    "indicator": sig.summarize_matcher_rule(),
                                    "trigger": trigger,
                                    "module": type(self),
                                }
                            )
                        )

        # check whois data for unregistered and expiring domains
        if self.cname_whoismanager.whois_result:
            for whois_finding in self.cname_whoismanager.analyzeWHOIS():
                findings.append(
                    Finding(
                        {
                            "target": self.target_dnsmanager.target,
                            "description": f"CNAME {whois_finding}",
                            "confidence": "CONFIRMED",
                            "signature": "N/A",
                            "indicator": "Whois Data",
                            "trigger": self.subject,
                            "module": type(self),
                        }
                    )
                )

        return findings
