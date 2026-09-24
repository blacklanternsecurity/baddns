from baddns.base import BadDNS_base

from baddns.lib.dnsmanager import DNSManager
from baddns.lib.dnswalk import DnsWalk
from baddns.lib.findings import Finding
from baddns.lib.whoismanager import WhoisManager

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import logging
import tldextract

log = logging.getLogger(__name__)


class BadDNS_ns(BadDNS_base):
    name = "NS"
    description = "Check for dangling NS records, and interrogate them for takeover opportunities"

    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)

        self._dnswalk_kwargs = kwargs

        self.target_dnsmanager = DNSManager(
            target, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers
        )
        # registered domain -> (WhoisManager, [nameserver hostnames under it])
        self.ns_whois = {}
        # (nameserver, signature) pairs that answered non-authoritatively for a live zone
        self.lame_nameservers = []

    @staticmethod
    def _is_lame(response_msg):
        """True if a nameserver answered but is not authoritative for the zone; None if it didn't answer."""
        if response_msg is None:
            return None
        rcode = response_msg.rcode()
        if rcode in (dns.rcode.REFUSED, dns.rcode.SERVFAIL, dns.rcode.NOTAUTH):
            return True
        if rcode in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            return not bool(response_msg.flags & dns.flags.AA)
        return None

    def _positive_nosoa_signature(self, nameserver):
        for sig in self.signatures:
            if sig.signature["mode"] == "dns_nosoa" and not sig.signature.get("negative_signature", False):
                if any(pattern in nameserver for pattern in sig.signature["identifiers"]["nameservers"]):
                    return sig
        return None

    async def _dispatch_ns_whois(self, nameservers):
        for nameserver in nameservers:
            registered = tldextract.extract(nameserver).registered_domain or nameserver
            if registered in self.ns_whois:
                self.ns_whois[registered][1].append(nameserver)
                continue
            manager = WhoisManager(nameserver)
            await manager.dispatchWHOIS()
            self.ns_whois[registered] = (manager, [nameserver])

    async def _dispatch_partial_lame(self, dnswalk, nameservers):
        """For a live zone, find individual delegated nameservers at claimable providers that don't serve it.

        Only nameservers matching a positive dns_nosoa signature are checked. A nameserver is reported only
        if it responded non-authoritatively on two separate queries; timeouts and errors never count.
        """
        for nameserver in nameservers:
            sig = self._positive_nosoa_signature(nameserver)
            if not sig:
                continue
            ips = await dnswalk.a_resolve(nameserver)
            if not ips:
                continue
            verdicts = []
            for _ in range(2):
                query = dns.message.make_query(self.target, dns.rdatatype.SOA)
                response_msg, _used_tcp = await dnswalk.raw_query_with_retry(query, ips[0])
                verdicts.append(self._is_lame(response_msg))
            if verdicts == [True, True]:
                log.debug(
                    f"Nameserver [{nameserver}] does not serve [{self.target}] (lame at {sig.signature['service_name']})"
                )
                self.lame_nameservers.append((nameserver, sig))

    async def _dispatch(self):
        # omit everything except CNAME. If there is a CNAME chain, we want to run against the end of it.
        await self.target_dnsmanager.dispatchDNS(omit_types=["A", "AAAA", "MX", "NS", "SOA", "TXT", "NSEC"])

        if self.target_dnsmanager.answers["CNAME"] != None:
            self.infomsg(
                f"Detected CNAME(S). Will set target to end of CNAME chain: [{self.target_dnsmanager.answers['CNAME'][-1]}]"
            )
            self.target_dnsmanager.target = self.target_dnsmanager.answers["CNAME"][-1]
            self.target = self.target_dnsmanager.answers["CNAME"][-1]
            self.target_dnsmanager.reset_answers()

        await self.target_dnsmanager.dispatchDNS(omit_types=["A", "AAAA", "CNAME", "MX", "NS", "TXT", "NSEC"])

        dnswalk = DnsWalk(
            self.target_dnsmanager,
            **{
                k: v
                for k, v in self._dnswalk_kwargs.items()
                if k in ("raw_query_max_retries", "raw_query_timeout", "raw_query_retry_wait")
            },
        )
        self.target_dnsmanager.answers["NS"] = await dnswalk.ns_trace(self.target)
        nameservers = self.target_dnsmanager.answers["NS"] or []
        await self._dispatch_ns_whois(nameservers)
        # Fully lame delegations (no SOA) are handled by the signature checks in analyze()
        if nameservers and self.target_dnsmanager.answers["SOA"] is not None:
            await self._dispatch_partial_lame(dnswalk, nameservers)
        return True

    @staticmethod
    def get_substring_matches(nameservers, strings):
        matched_nameservers = set()
        matched_signatures = set()

        for ns in nameservers:
            for s in strings:
                if s in ns:
                    matched_nameservers.add(ns)
                    matched_signatures.add(s)

        if not matched_nameservers and not matched_signatures:
            return None

        return list(matched_nameservers), list(matched_signatures)

    def _whois_findings(self):
        findings = []
        for registered, (manager, nameservers) in self.ns_whois.items():
            for whois_finding in manager.analyzeWHOIS():
                findings.append(
                    Finding(
                        {
                            "target": self.target_dnsmanager.target,
                            "description": f"Nameserver domain {whois_finding}: whoever registers [{registered}] controls this zone",
                            "confidence": "CONFIRMED",
                            "severity": "HIGH",
                            "signature": "NS",
                            "indicator": "Whois Data",
                            "trigger": nameservers,
                            "module": type(self),
                        }
                    )
                )
        return findings

    def _partial_lame_findings(self):
        findings = []
        for nameserver, sig in self.lame_nameservers:
            findings.append(
                Finding(
                    {
                        "target": self.target_dnsmanager.target,
                        "description": "Partially dangling NS delegation: a delegated nameserver does not serve the zone and is at a claimable provider",
                        "confidence": sig.signature.get("confidence", "MEDIUM"),
                        "severity": "MEDIUM",
                        "signature": sig.signature["service_name"],
                        "indicator": "Non-authoritative answer from delegated nameserver (confirmed twice)",
                        "trigger": nameserver,
                        "module": type(self),
                    }
                )
            )
        return findings

    def analyze(self):
        log.debug("Staring analysis")
        findings = self._whois_findings() + self._partial_lame_findings()
        if self.target_dnsmanager.answers["NS"] and len(self.target_dnsmanager.answers["NS"]) > 0:
            target_nameservers = self.target_dnsmanager.answers["NS"]
            log.debug("Nameserver(s) found. Continuing...")
        else:
            return findings or False
        if self.target_dnsmanager.answers["SOA"] == None:
            log.debug("No SOA record found w/nameservers present")
            r = None
            # Check positive signatures first
            for sig in self.signatures:
                if sig.signature["mode"] == "dns_nosoa" and not sig.signature.get("negative_signature", False):
                    sig_nameservers = [ns for ns in sig.signature["identifiers"]["nameservers"]]
                    r = self.get_substring_matches(target_nameservers, sig_nameservers)
                    if r:
                        findings.append(
                            Finding(
                                {
                                    "target": self.target_dnsmanager.target,
                                    "description": "Dangling NS Records (NS records without SOA) with known impact",
                                    "confidence": sig.signature.get("confidence", "HIGH"),
                                    "severity": "MEDIUM",
                                    "signature": sig.signature["service_name"],
                                    "indicator": f"DnsWalk Analysis with signature match: {r[1]}",
                                    "trigger": target_nameservers,
                                    "module": type(self),
                                }
                            )
                        )
                        log.debug(
                            f"Found match for for target nameservers {', '.join(target_nameservers)} with signature [{sig.signature['service_name']}]"
                        )
                        return findings
            # Check negative signatures before falling back to generic
            if not self.disable_negative_signatures:
                for sig in self.signatures:
                    if sig.signature["mode"] == "dns_nosoa" and sig.signature.get("negative_signature", False):
                        sig_nameservers = [ns for ns in sig.signature["identifiers"]["nameservers"]]
                        r = self.get_substring_matches(target_nameservers, sig_nameservers)
                        if r:
                            log.debug(
                                f"Negative signature match [{sig.signature['service_name']}] for nameservers {', '.join(target_nameservers)}, suppressing generic finding"
                            )
                            return findings
            log.debug(
                f"No signature found, falling back to report generic dangling NS record for nameservers: [{', '.join(target_nameservers)}]]"
            )
            findings.append(
                Finding(
                    {
                        "target": self.target_dnsmanager.target,
                        "description": "Dangling NS Records (NS records without SOA)",
                        "confidence": "LOW",
                        "severity": "MEDIUM",
                        "signature": "GENERIC",
                        "indicator": "DNSWalk Analysis",
                        "trigger": target_nameservers,
                        "module": type(self),
                    }
                )
            )

        return findings
