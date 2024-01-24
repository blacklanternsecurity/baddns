from baddns.base import BadDNS_base
from .errors import BadDNSFindingException
import logging

log = logging.getLogger(__name__)


class Finding:
    def __init__(self, finding_dict):
        self.finding_dict = {}
        target = finding_dict.get("target", None)
        self.finding_dict["target"] = target
        if not target:
            raise BadDNSFindingException("Target is required in a Finding")

        description = finding_dict.get("description", "N/A")
        if not isinstance(description, str):
            raise BadDNSFindingException("description field must be a str")
        self.finding_dict["description"] = description

        confidence = finding_dict.get("confidence", None)
        if confidence == None or confidence not in ["CONFIRMED", "PROBABLE", "POSSIBLE", "UNLIKELY"]:
            raise BadDNSFindingException(
                "Confidence must be present and must be one of: CONFIRMED, PROBABLE, POSSIBLE, UNLIKELY"
            )
        self.finding_dict["confidence"] = confidence

        signature = finding_dict.get("signature", None)
        if not signature:
            raise BadDNSFindingException("signature is required in a Finding")
        self.finding_dict["signature"] = signature

        indicator = finding_dict.get("indicator", None)
        if not indicator:
            raise BadDNSFindingException("indicator is required in a Finding")
        self.finding_dict["indicator"] = indicator

        trigger = finding_dict.get("trigger", None)
        if not indicator:
            raise BadDNSFindingException("trigger is required in a Finding")
        if isinstance(trigger, list):
            trigger = ", ".join(trigger)
        elif isinstance(trigger, str):
            pass
        else:
            raise BadDNSFindingException("trigger must be either str or list")
        self.finding_dict["trigger"] = trigger

        module = finding_dict.get("module", None)
        if not module:
            raise BadDNSFindingException("Module is required in a Finding")
        if not issubclass(module, BadDNS_base):
            raise BadDNSFindingException("Module was not a valid baddns module")
        self.finding_dict["module"] = module.name

        found_domains = finding_dict.get("found_domains", None)
        if found_domains:
            self.finding_dict["found_domains"] = found_domains

    def to_dict(self):
        return self.finding_dict

    def __str__(self):
        return str(self.finding_dict)
