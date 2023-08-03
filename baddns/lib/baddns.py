import os
import yaml

from .signature import BadDNSSignature
from .errors import BadDNSSignatureException


class BadDNS:
    def __init__(self, target):
        self.target = target
        self.signatures = []
        self.load_signatures()

    def load_signatures(self):
        print("in load signatures")
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

    def build_http_request(self):
        pass

    def build_dns_request(self):
        pass

    def check(self):
        for sig in self.signatures:
            print(sig)
