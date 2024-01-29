import os
import yaml
import logging
import pkg_resources

log = logging.getLogger(__name__)

from .lib.signature import BadDNSSignature
from .lib.errors import BadDNSSignatureException


class BadDNS_base:
    def __init__(
        self,
        target,
        http_client_class=None,
        dns_client=None,
        signatures_dir=None,
        custom_nameservers=None,
        cli=False,
        **kwargs,
    ):
        self.target = self.set_target(target)
        self.http_client_class = http_client_class
        self.dns_client = dns_client
        self.signatures_dir = signatures_dir
        self.signatures = []
        self.load_signatures(signatures_dir)
        self.custom_nameservers = custom_nameservers
        self.parent_class = kwargs.get("parent_class", "self")
        self.cli = cli

    # hook to allow external manipulation of target assignment
    def set_target(self, target):
        return target

    def infomsg(self, msg):
        if self.cli:
            log.info(msg)
        else:
            log.debug(msg)

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


def get_all_modules(*args, **kwargs):
    return [m for m in BadDNS_base.__subclasses__()]
