import os
import yaml
import httpx
import dns.asyncresolver

from .signature import BadDNSSignature
from .errors import BadDNSSignatureException


class DNSManager:
    dns_record_types = ["A", "AAAA", "MX", "CNAME", "NS", "SOA", "TXT"]

    def __init__(self, target):
        self.target = target
        self.answers = {key: None for key in self.dns_record_types}

    async def dispatchDNS(self):
        resolver = dns.asyncresolver.Resolver()
        for rdatatype in self.dns_record_types:
            try:
                self.answers[rdatatype] = await resolver.resolve(self.target, rdatatype)
            except dns.resolver.NoAnswer:
                pass
        print(self.answers)


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
        except httpx.RequestError as exc:
            print(f"An error occurred while requesting {exc.request.url!r}: {exc}")


class BadDNS:
    def __init__(self, target):
        self.target = target
        self.signatures = []
        self.load_signatures()
        self.httpmanager = HttpManager(self.target)
        self.dnsmanager = DNSManager(self.target)

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

    async def dispatchConnections(self):
        await self.httpmanager.dispatchHttp()
        await self.dnsmanager.dispatchDNS()

    def analyze(self):
        print(self.httpmanager.http_allowredirects_results)
        print(self.httpmanager.http_denyredirects_results)
        print(self.httpmanager.https_allowredirects_results)
        print(self.httpmanager.https_denyredirects_results)


#       for sig in self.signatures:
#          print(sig)
