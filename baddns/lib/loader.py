import os
import yaml
import logging
import pkg_resources

log = logging.getLogger(__name__)

from .errors import BadDNSSignatureException
from .signature import BadDNSSignature


def load_signatures(signatures_dir=None):
    signatures = []
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
                    signatures.append(signature)
            except BadDNSSignatureException as e:
                log.error(f"Error loading signature from {filename}: {e}")
    if len(signatures) == 0:
        raise BadDNSSignatureException(f"No signatures were successfuly loaded from [{signatures_dir}]")
    else:
        log.debug(f"Loaded [{str(len(signatures))}] signatures from [{signatures_dir}]")

    return signatures
