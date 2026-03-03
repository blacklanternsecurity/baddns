from baddns.base import BadDNS_base
from .errors import BadDNSFindingException
import logging
import json

log = logging.getLogger(__name__)

CONFIDENCE_LEVELS = ("CONFIRMED", "HIGH", "MODERATE", "LOW", "UNKNOWN")
SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")


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
        if confidence == None or confidence not in ["CONFIRMED", "HIGH", "MODERATE", "LOW", "UNKNOWN"]:
            raise BadDNSFindingException(
                "Confidence must be present and must be one of: CONFIRMED, HIGH, MODERATE, LOW, UNKNOWN"
            )
        self.finding_dict["confidence"] = confidence

        severity = finding_dict.get("severity", None)
        if severity == None or severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            raise BadDNSFindingException(
                "Severity must be present and must be one of: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL"
            )
        self.finding_dict["severity"] = severity

        signature = finding_dict.get("signature", None)
        if not signature:
            raise BadDNSFindingException("signature is required in a Finding")
        self.finding_dict["signature"] = signature

        indicator = finding_dict.get("indicator", None)
        if not indicator:
            raise BadDNSFindingException("indicator is required in a Finding")
        self.finding_dict["indicator"] = indicator

        trigger = finding_dict.get("trigger", None)
        if not trigger:
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

    @property
    def name(self):
        """Display name: 'BadDNS {module} {signature}' (omit signature if N/A)."""
        module_name = self.finding_dict["module"]
        sig = self.finding_dict["signature"]
        if sig and sig != "N/A":
            return f"BadDNS {module_name} {sig}"
        return f"BadDNS {module_name}"

    def to_dict(self):
        return self.finding_dict

    def meets_minimum(self, min_confidence=None, min_severity=None):
        if min_confidence:
            if CONFIDENCE_LEVELS.index(self.finding_dict["confidence"]) > CONFIDENCE_LEVELS.index(min_confidence):
                return False
        if min_severity:
            if SEVERITY_LEVELS.index(self.finding_dict["severity"]) > SEVERITY_LEVELS.index(min_severity):
                return False
        return True

    def to_json(self):
        return json.dumps(self.finding_dict)

    def __str__(self):
        return str(self.finding_dict)
