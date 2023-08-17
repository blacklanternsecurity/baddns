import os
import ssl
import yaml
import httpx
import whois
import logging
import tldextract
import pkg_resources
import dns.asyncresolver
from datetime import date

from .matcher import Matcher
from .signature import BadDNSSignature
from .errors import BadDNSSignatureException

log = logging.getLogger(__name__)


class DNSManager:
    dns_record_types = ["A", "AAAA", "MX", "CNAME", "NS", "SOA", "TXT"]

    def __init__(self, target, dns_client=None, custom_nameservers=None):
        if not dns_client:
            self.dns_client = dns.asyncresolver.Resolver()
        else:
            self.dns_client = dns_client

        if custom_nameservers:
            self.dns_client.nameservers = custom_nameservers

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

    async def do_resolve(self, target, rdatatype):
        try:
            r = await self.dns_client.resolve(target, rdatatype)
        except dns.resolver.NoAnswer:
            self.answers["NoAnswer"] = True
            return
        except dns.resolver.NXDOMAIN:
            self.answers["NXDOMAIN"] = True
            return
        except dns.resolver.LifetimeTimeout as e:
            log.debug(f"Dns Timeout: {e}")
            return
        except dns.resolver.NoNameservers as e:
            log.debug(f"No nameservers: {e}")
            return
        if r and len(r) > 0:
            if rdatatype == "A":
                self.ips.extend(self.get_ipv4(r))
            elif rdatatype == "AAAA":
                self.ips.extend(self.get_ipv6(r))

            elif rdatatype == "CNAME":
                cname_chain = []

                while 1:
                    result_cname = r[0].to_text().rstrip(".")
                    cname_chain.append(result_cname)
                    target = result_cname
                    try:
                        r = await self.dns_client.resolve(target, "CNAME")
                        if len(r) == 0:
                            break
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        break
                return cname_chain
            return r

    async def dispatchDNS(self, skip_cname=False):
        log.debug(f"attempting to resolve {self.target}")
        for rdatatype in self.dns_record_types:
            if rdatatype == "CNAME" and skip_cname == True:
                continue
            self.answers[rdatatype] = await self.do_resolve(self.target, rdatatype)


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
    def __init__(self, target, http_client_class=None):
        if not http_client_class:
            http_client_class = httpx.AsyncClient
        self.http_client = http_client_class(timeout=5, verify=False)
        self.target = target
        self.http_allowredirects_results = None
        self.http_denyredirects_results = None
        self.https_allowredirects_results = None
        self.https_denyredirects_results = None

    async def dispatchHttp(self):
        try:
            self.http_allowredirects_results = await self.http_client.get(
                f"http://{self.target}/", follow_redirects=True
            )
            self.http_denyredirects_results = await self.http_client.get(
                f"http://{self.target}/", follow_redirects=False
            )
            self.https_allowredirects_results = await self.http_client.get(
                f"https://{self.target}/", follow_redirects=True
            )
            self.https_denyredirects_results = await self.http_client.get(
                f"https://{self.target}/", follow_redirects=False
            )
        except httpx.RequestError as e:
            log.debug(f"An error occurred while requesting {e.request.url!r}: {e}")
        except httpx.ConnectError as e:
            log.debug(f"Http Connect Error {e.request.url!r}: {e}")
        except ssl.SSLError as e:
            log.debug(f"SSL Error: {e}")


class BadDNS_base:
    def __init__(self, target, http_client_class=None, dns_client=None, signatures_dir=None, custom_nameservers=None):
        self.http_client_class = http_client_class
        self.dns_client = dns_client
        self.target = target
        self.signatures = []
        findings = []
        self.load_signatures(signatures_dir)
        self.custom_nameservers = custom_nameservers

    def load_signatures(self, signatures_dir=None):
        if signatures_dir:
            if not os.path.exists(signatures_dir):
                raise BadDNSSignatureException(f"Signatures directory [{signatures_dir}] does not exist")
        else:
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
        if len(self.signatures) == 0:
            raise BadDNSSignatureException(f"No signatures were successfuly loaded from [{signatures_dir}]")
        else:
            log.debug(f"Loaded [{str(len(self.signatures))}] signatures from [{signatures_dir}]")


class BadDNS_ns(BadDNS_base):
    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)
        log.info(f"Starting NS Module with target [{target}]")
        self.target_dnsmanager = DNSManager(
            target, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers
        )

    async def dispatch(self):
        await self.target_dnsmanager.dispatchDNS()
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

    def analyze(self):
        findings = []
        if self.target_dnsmanager.answers["NS"] != None:
            target_nameservers = [ns.to_text() for ns in self.target_dnsmanager.answers["NS"]]
            log.debug("Nameserver(s) found. Continuing...")
        else:
            return False

        if self.target_dnsmanager.answers["SOA"] == None:
            log.debug("No SOA record found w/nameservers present")

            signature_name = "GENERIC"
            matching_signatures = None
            r = None
            for sig in self.signatures:
                if sig.signature["mode"] == "dns_nosoa":
                    sig_nameservers = [ns for ns in sig.signature["identifiers"]["nameservers"]]
                    r = self.get_substring_matches(target_nameservers, sig_nameservers)
                    if r:
                        matching_signatures = r[1]
                        signature_name = sig.signature["service_name"]
                        log.debug(
                            f"Found match for for target nameservers {', '.join(target_nameservers)} with signature [{sig.signature['service_name']}] "
                        )
                        break

            findings.append(
                {
                    "target": self.target_dnsmanager.target,
                    "nameservers": [ns.to_text() for ns in self.target_dnsmanager.answers["NS"]],
                    "signature_name": signature_name,
                    "matching_signatures": matching_signatures,
                    "technique": "NS RECORD WITHOUT SOA",
                }
            )

        return findings


class BadDNS_cname(BadDNS_base):
    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)
        log.info(f"Starting CNAME Module with target [{target}]")
        self.target_dnsmanager = DNSManager(target, dns_client=self.dns_client)
        self.target_httpmanager = None
        self.cname_dnsmanager = None
        self.cname_whoismanager = None

    async def dispatch(self):
        await self.target_dnsmanager.dispatchDNS()

        if self.target_dnsmanager.answers["CNAME"] != None:
            log.info(
                f"Found CNAME(S) [{' -> '.join([self.target_dnsmanager.target] + self.target_dnsmanager.answers['CNAME'])}]"
            )
        else:
            log.info("No CNAME Found :/")
            return False

        self.cname_dnsmanager = DNSManager(self.target_dnsmanager.answers["CNAME"][-1], dns_client=self.dns_client)
        await self.cname_dnsmanager.dispatchDNS(skip_cname=True)

        # if the domain resolves, we can try for HTTP connections
        if not self.cname_dnsmanager.answers["NXDOMAIN"]:
            log.debug("CNAME resolved correctly, proceeding with HTTP dispatch")
            self.target_httpmanager = HttpManager(self.target, http_client_class=self.http_client_class)
            await self.target_httpmanager.dispatchHttp()
            log.debug("HTTP dispatch complete")
        # if the cname doesn't resolve, we still need to see if the base domain is unregistered
        # even if it is registered, we still use whois to check for expired domains
        log.debug("performing WHOIS lookup")
        self.cname_whoismanager = WhoisManager(self.target_dnsmanager.answers["CNAME"][-1])
        await self.cname_whoismanager.dispatchWHOIS()
        log.debug("WHOIS dispatch complete")
        return True

    def analyze(self):
        findings = []
        if self.cname_dnsmanager.answers["NXDOMAIN"]:
            signature_name = "Generic Dangling CNAME"
            matching_domain = None

            log.info(f"Got NXDOMAIN for CNAME {self.cname_dnsmanager.target}. Checking against signatures...")
            for sig in self.signatures:
                if sig.signature["mode"] == "dns_nxdomain":
                    log.debug(f"Trying signature {sig.signature['service_name']}")
                    sig_cnames = [c["value"] for c in sig.signature["identifiers"]["cnames"]]
                    for sig_cname in sig_cnames:
                        log.debug(f"Checking CNAME {self.cname_dnsmanager.target} against {sig_cname}")
                        if self.cname_dnsmanager.target.endswith(sig_cname):
                            log.debug(f"CNAME {self.cname_dnsmanager.target} Vulnerable ({sig_cname})")
                            signature_name = sig.signature["service_name"]
                            matching_domain = sig_cname
                            break

            findings.append(
                {
                    "target": self.target_dnsmanager.target,
                    "cnames": self.target_dnsmanager.answers["CNAME"],
                    "signature_name": signature_name,
                    "matching_domain": matching_domain,
                    "technique": "CNAME NXDOMAIN",
                }
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
                            cname_dict["value"] in self.target_dnsmanager.answers["CNAME"][-1]
                            for cname_dict in sig.signature["identifiers"]["cnames"]
                        ):
                            log.debug(
                                f"no match for {sig.signature['identifiers']['cnames']} for in {self.target_dnsmanager.answers['CNAME'][-1]}"
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
                        findings.append(
                            {
                                "target": self.target_dnsmanager.target,
                                "cnames": self.target_dnsmanager.answers["CNAME"],
                                "signature_name": sig.signature["service_name"],
                                "technique": "HTTP String Match",
                            }
                        )

        # check whois data for expiring domains
        log.debug("analyzing whois results")
        if self.cname_whoismanager.whois_result:
            # check for unregistered CNAME
            if self.cname_whoismanager.whois_result["type"] == "error":
                log.debug("whois result was an error")
                if "No match for" in self.cname_whoismanager.whois_result["data"]:
                    findings.append(
                        {
                            "target": self.target_dnsmanager.target,
                            "cnames": self.target_dnsmanager.answers["CNAME"],
                            "signature_name": None,
                            "matching_domain": None,
                            "technique": "CNAME unregistered",
                        }
                    )

            # check for expired domain
            elif self.cname_whoismanager.whois_result["type"] == "response":
                log.debug("whois resulted in a response")
                expiration_data = self.cname_whoismanager.whois_result["data"]["expiration_date"]
                if isinstance(expiration_data, list):
                    expiration_date = expiration_data[0]
                else:
                    expiration_date = expiration_data

                current_date = date.today()
                if expiration_date.date() < current_date:
                    log.info(
                        f"Current Date ({current_date.strftime('%Y-%m-%d')}) after Expiration Date ({expiration_date.date().strftime('%Y-%m-%d')})"
                    )
                    findings.append(
                        {
                            "target": self.target_dnsmanager.target,
                            "cnames": self.target_dnsmanager.answers["CNAME"],
                            "signature_name": None,
                            "matching_domain": None,
                            "technique": "CNAME Base Domain Expired",
                            "expiration_date": expiration_date.strftime("%Y-%m-%d %H:%M:%S"),
                        }
                    )
                else:
                    log.debug(f"Domain {self.cname_dnsmanager.target} is not expired")

        else:
            log.debug("whois_result was NoneType")

        return findings
