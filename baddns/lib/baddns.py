import os
import ssl
import yaml
import httpx
import dns.asyncresolver

from .matcher import Matcher
from .signature import BadDNSSignature
from .errors import BadDNSSignatureException


class DNSManager:
    dns_record_types = ["A", "AAAA", "MX", "CNAME", "NS", "SOA", "TXT"]

    def __init__(self, target):
        self.target = target
        self.answers = {key: None for key in self.dns_record_types}
        self.answers.update({"NoAnswer": False, "NXDOMAIN": False})

    async def dispatchDNS(self):
        resolver = dns.asyncresolver.Resolver()
        for rdatatype in self.dns_record_types:
            try:
                self.answers[rdatatype] = await resolver.resolve(self.target, rdatatype)
            except dns.resolver.NoAnswer:
                self.answers["NoAnswer"] = True
            except dns.resolver.NXDOMAIN:
                self.answers["NXDOMAIN"] = True


class HttpManager:
    def __init__(self, target):
        self.target = target
        self.http_allowredirects_results = None
        self.http_denyredirects_results = None
        self.https_allowredirects_results = None
        self.https_denyredirects_results = None
        self.http_allowredirects = httpx.AsyncClient(follow_redirects=True, timeout=5)
        self.http_denyredirects = httpx.AsyncClient(follow_redirects=False, timeout=5)
        self.https_allowredirects = httpx.AsyncClient(follow_redirects=True, timeout=5, verify=False)
        self.https_denyredirects = httpx.AsyncClient(follow_redirects=False, timeout=5, verify=False)

    async def dispatchHttp(self):
        try:
            self.http_allowredirects_results = await self.http_allowredirects.get(f"http://{self.target}/")
            self.http_denyredirects_results = await self.http_allowredirects.get(f"http://{self.target}/")
            self.https_allowredirects_results = await self.http_allowredirects.get(f"https://{self.target}/")
            self.https_denyredirects_results = await self.http_allowredirects.get(f"https://{self.target}/")
        except httpx.RequestError as e:
            print(f"An error occurred while requesting {e.request.url!r}: {e}")
        except httpx.ConnectError as e:
            print(f"Http Connect Error {e.request.url!r}: {e}")
        except ssl.SSLError as e:
            print(f"SSL Error: {e}")


class BadDNS_base:
    def __init__(self, target):
        self.target = target
        self.signatures = []
        self.load_signatures()

    def load_signatures(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        signatures_dir = os.path.join(dir_path, "../../signatures")

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
                    print(f"Error loading signature from {filename}: {e}")


class BadDNS_cname(BadDNS_base):
    def __init__(self, target):
        super().__init__(target)
        self.found_cname = None
        self.target_dnsmanager = DNSManager(target)

    async def dispatch(self):
        await self.target_dnsmanager.dispatchDNS()

        if self.target_dnsmanager.answers["CNAME"]:
            self.found_cname = self.target_dnsmanager.answers["CNAME"][0].to_text().rstrip(".")
            print(f"found_cname: {self.found_cname}")
        else:
            print("didnt find cname, exiting")
            return False

        self.cname_dnsmanager = DNSManager(self.found_cname)
        self.cname_httpmanager = HttpManager(self.found_cname)

        await self.cname_dnsmanager.dispatchDNS()
        await self.cname_httpmanager.dispatchHttp()
        return True

    def analyze(self):
        http_results = [
            self.cname_httpmanager.http_allowredirects_results,
            self.cname_httpmanager.http_denyredirects_results,
            self.cname_httpmanager.https_allowredirects_results,
            self.cname_httpmanager.https_denyredirects_results,
        ]

        for sig in self.signatures:
            #      print(sig.signature["service_name"])
            if sig.signature["mode"] == "http":
                if len(sig.signature["identifiers"]["cnames"]) > 0:
                    # The signature specifies cnames, therefore, we need to match the base domain before proceeding
                    if not any(
                        cname_dict["value"] in self.found_cname
                        for cname_dict in sig.signature["identifiers"]["cnames"]
                    ):
                        #  print(f"no match for {sig.signature['identifiers']['cnames']} for in {self.found_cname}")
                        continue

                m = Matcher(sig.signature["matcher_rule"])
                if any(m.is_match(hr) for hr in http_results if hr is not None):
                    print("VULNERABLE!!!!!!!!!!!!!")
                    print(sig.signature["service_name"])
                    print(sig.signature["mode"])
                    print(sig.signature["matcher_rule"])
