import os
import ssl
import yaml
import httpx
import whois
import logging
import tldextract
import pkg_resources
import dns.asyncresolver

from .matcher import Matcher
from .signature import BadDNSSignature
from .errors import BadDNSSignatureException

log = logging.getLogger(__name__)


class DNSManager:
    dns_record_types = ["A", "AAAA", "MX", "CNAME", "NS", "SOA", "TXT"]

    def __init__(self, target, dns_client=None):
        if not dns_client:
            self.dns_client = dns.asyncresolver.Resolver()
        else:
            self.dns_client = dns_client
        self.target = target
        self.answers = {key: None for key in self.dns_record_types}
        self.answers.update({"NoAnswer": False, "NXDOMAIN": False})
        self.ips = []

    @staticmethod
    def get_ipv4(a_records):
        ipv4 = []
        for answer in a_records:
            log.debug(f"Found IPV4 address: {answer}")
            ipv4.append(str(answer))
        return ipv4

    @staticmethod
    def get_ipv6(aaaa_records):
        ipv6 = []
        for answer in aaaa_records:
            log.debug(f"Found IPV6 address: {answer}")
            ipv6.append(str(answer))
        return ipv6

    async def dispatchDNS(self):
        log.debug(f"attempting to resolve {self.target}")
        for rdatatype in self.dns_record_types:
            try:
                self.answers[rdatatype] = await self.dns_client.resolve(self.target, rdatatype)
                if rdatatype == "A":
                    self.ips.extend(self.get_ipv4(self.answers[rdatatype]))
                if rdatatype == "AAAA":
                    self.ips.extend(self.get_ipv6(self.answers[rdatatype]))
            except dns.resolver.NoAnswer:
                self.answers["NoAnswer"] = True
            except dns.resolver.NXDOMAIN:
                self.answers["NXDOMAIN"] = True
            except dns.resolver.LifetimeTimeout as e:
                log.debug(f"Dns Timeout: {e}")
            except dns.resolver.NoNameservers as e:
                log.debug(f"No nameservers: {e}")


class WhoisManager:
    def __init__(self, target):
        self.target = target
        self.whois_result = None

    async def dispatchWHOIS(self):
        ext = tldextract.extract(self.target)
        log.debug(f"Extracted base domain [{ext.registered_domain}] from [{self.target}]")
        log.debug(f"Submitting WHOIS query for {ext.registered_domain}")
        try:
            w = whois.whois(ext.registered_domain)
            log.debug(f"Got response to whois request for {ext.registered_domain}")
            self.whois_result = {"type": "response", "data": w}
        except whois.parser.PywhoisError as e:
            log.debug(f"Got PywhoisError for whois request for {ext.registered_domain}")
            self.whois_result = {"type": "error", "data": str(e)}


class HttpManager:
    def __init__(self, target, http_client=None):
        if not http_client:
            http_client = httpx.AsyncClient
        self.target = target
        self.http_allowredirects_results = None
        self.http_denyredirects_results = None
        self.https_allowredirects_results = None
        self.https_denyredirects_results = None
        self.http_allowredirects = http_client(follow_redirects=True, timeout=5, verify=False)
        self.http_denyredirects = http_client(follow_redirects=False, timeout=5, verify=False)
        self.https_allowredirects = http_client(follow_redirects=True, timeout=5, verify=False)
        self.https_denyredirects = http_client(follow_redirects=False, timeout=5, verify=False)

    async def dispatchHttp(self):
        try:
            self.http_allowredirects_results = await self.http_allowredirects.get(f"http://{self.target}/")
            self.http_denyredirects_results = await self.http_allowredirects.get(f"http://{self.target}/")
            self.https_allowredirects_results = await self.http_allowredirects.get(f"https://{self.target}/")
            self.https_denyredirects_results = await self.http_allowredirects.get(f"https://{self.target}/")
        except httpx.RequestError as e:
            log.debug(f"An error occurred while requesting {e.request.url!r}: {e}")
        except httpx.ConnectError as e:
            log.debug(f"Http Connect Error {e.request.url!r}: {e}")
        except ssl.SSLError as e:
            log.debug(f"SSL Error: {e}")


class BadDNS_base:
    def __init__(self, target, http_client=None, dns_client=None):
        self.http_client = http_client
        self.dns_client = dns_client
        self.target = target
        self.signatures = []
        self.load_signatures()

    def load_signatures(self):
        signatures_dir = pkg_resources.resource_filename("baddns", "signatures")
        log.debug(f"attempting to load signatures from: {signatures_dir}")
        for filename in os.listdir(signatures_dir):
            if filename.endswith(".yml"):
                file_path = os.path.join(signatures_dir, filename)

                # Open each file and load the YAML contents
                try:
                    with open(file_path, "r") as file:
                        signature_data = yaml.safe_load(file)
                        signature = BadDNSSignature()
                        signature.initialize(**signature_data)
                        self.signatures.append(signature)
                except BadDNSSignatureException as e:
                    log.error(f"Error loading signature from {filename}: {e}")


class BadDNS_cname(BadDNS_base):
    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)
        log.info(f"Starting CNAME Module with target [{target}]")
        self.found_cname = None
        self.target_dnsmanager = DNSManager(target, dns_client=self.dns_client)
        self.target_httpmanager = None
        self.cname_dnsmanager = None
        self.cname_whoismanager = None

    async def dispatch(self):
        await self.target_dnsmanager.dispatchDNS()

        if self.target_dnsmanager.answers["CNAME"]:
            self.found_cname = self.target_dnsmanager.answers["CNAME"][0].to_text().rstrip(".")
            log.info(f"Found CNAME [{self.found_cname}]")
        else:
            log.info("No CNAME Found :/")
            return False

        self.cname_dnsmanager = DNSManager(self.found_cname, dns_client=self.dns_client)
        await self.cname_dnsmanager.dispatchDNS()

        # if the domain resolves, we can try for HTTP connections
        if not self.cname_dnsmanager.answers["NXDOMAIN"]:
            log.debug("CNAME resolved correctly, proceeding with HTTP dispatch")
            self.target_httpmanager = HttpManager(self.target, http_client=self.http_client)
            await self.target_httpmanager.dispatchHttp()
            log.debug("HTTP dispatch complete")
        # if the cname doesn't resolve, we still need to see if the base domain is unregistered
        else:
            log.debug("CNAME didn't resolve, checking for unregistered base domain")
            self.cname_whoismanager = WhoisManager(self.found_cname)
            await self.cname_whoismanager.dispatchWHOIS()
            log.debug("WHOIS dispatch complete")
        return True

    def analyze(self):
        if self.cname_dnsmanager.answers["NXDOMAIN"]:
            log.info(f"Got NXDOMAIN for CNAME {self.cname_dnsmanager.target}. Checking against signatures...")
            for sig in self.signatures:
                if sig.signature["mode"] == "dns_nxdomain":
                    log.debug(f"Trying signature {sig.signature['service_name']}")
                    sig_cnames = [c["value"] for c in sig.signature["identifiers"]["cnames"]]
                    for sig_cname in sig_cnames:
                        log.debug(f"Checking CNAME {self.cname_dnsmanager.target} against {sig_cname}")
                        if self.cname_dnsmanager.target.endswith(sig_cname):
                            log.debug(f"CNAME {self.cname_dnsmanager.target} Vulnerable ({sig_cname})")
                            return {
                                "target": self.target_dnsmanager.target,
                                "cname": self.cname_dnsmanager.target,
                                "signature_name": sig.signature["service_name"],
                                "matching_domain": sig_cname,
                                "technique": "CNAME NXDOMAIN",
                            }

            log.debug("analyzing whois results")
            if self.cname_whoismanager.whois_result:
                if self.cname_whoismanager.whois_result["type"] == "error":
                    if "No match for" in self.cname_whoismanager.whois_result["data"]:
                        return {
                            "target": self.target_dnsmanager.target,
                            "cname": self.cname_dnsmanager.target,
                            "signature_name": None,
                            "matching_domain": None,
                            "technique": "CNAME unregistered",
                        }
                else:
                    log.warning("Place holder for unregistered domain signature")
            else:
                log.debug("whois_result was NoneType")
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
                            cname_dict["value"] in self.found_cname
                            for cname_dict in sig.signature["identifiers"]["cnames"]
                        ):
                            log.debug(
                                f"no match for {sig.signature['identifiers']['cnames']} for in {self.found_cname}"
                            )
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

                    m = Matcher(sig.signature["matcher_rule"])
                    log.debug("Checking for HTTP matches")
                    if any(m.is_match(hr) for hr in http_results if hr is not None):
                        log.debug(f"CNAME {self.cname_dnsmanager.target} Vulnerable")
                        log.debug(f"With matcher_rule {sig.signature['matcher_rule']}")
                        return {
                            "target": self.target_dnsmanager.target,
                            "cname": self.cname_dnsmanager.target,
                            "signature_name": sig.signature["service_name"],
                            "technique": "HTTP String Match",
                        }
