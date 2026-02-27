import os
import yaml
import logging
from importlib import resources

log = logging.getLogger(__name__)

from .errors import BadDNSSignatureException
from .signature import BadDNSSignature


def load_signatures(signatures_dir=None, signature_filter=None):
    signatures = []
    if signatures_dir:
        if not os.path.exists(signatures_dir):
            raise BadDNSSignatureException(f"Signatures directory [{signatures_dir}] does not exist")
    else:

        signatures_dir = resources.files("baddns") / "signatures"

    log.debug(f"attempting to load signatures from: {signatures_dir}")

    for filename in os.listdir(signatures_dir):
        if filename.endswith(".yml"):
            sig_name = filename[:-4]  # strip .yml
            if signature_filter and sig_name not in signature_filter:
                continue
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
        if signature_filter:
            raise BadDNSSignatureException(
                f"No signatures matched the provided filter: {', '.join(signature_filter)}"
            )
        raise BadDNSSignatureException(f"No signatures were successfuly loaded from [{signatures_dir}]")
    else:
        log.debug(f"Loaded [{str(len(signatures))}] signatures from [{signatures_dir}]")

    return signatures
