import re
import os
import sys
import yaml
import logging

from baddns.lib.httpmanager import header_items


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

# from lib.errors import BadDNSMatcherException

log = logging.getLogger(__name__)


class Matcher:
    def __init__(self, rules):
        if isinstance(rules, str):  # YAML input is a string
            try:
                self.rules = yaml.safe_load(rules)
            except yaml.YAMLError as e:
                raise ValueError(f"Error parsing YAML: {e}")
        elif isinstance(rules, dict):  # YAML input is a dict
            self.rules = rules
        else:
            raise TypeError("yaml_rules must be a YAML string or a dict")

    def _status(self, criteria):
        negative = criteria.get("negative", False)
        return self.response.status != criteria["status"] if negative else self.response.status == criteria["status"]

    @staticmethod
    def _header_text(headers):
        """Render headers as 'name: value' lines (names lowercased, duplicates kept) for word matching."""
        return "\n".join(f"{name.lower()}: {value}" for name, value in header_items(headers))

    def _word(self, criteria):
        words = criteria["words"]
        part = criteria.get("part", "body").lower()
        negative = criteria.get("negative", False)

        if part == "header":
            text = self._header_text(self.response.headers)
        elif part == "body":
            text = self.response.body

        # we can ignore this because are already adding these entries into the identifiers
        elif part in ("host", "cname"):
            return True
        else:
            # Signature validation rejects unknown parts at load time; never crash a scan over one
            log.warning(f"Unknown matcher part [{part}], treating as non-match")
            return False

        condition = criteria.get("condition", "and")
        if condition == "and":
            return not all(word in text for word in words) if negative else all(word in text for word in words)
        elif condition == "or":
            return not any(word in text for word in words) if negative else any(word in text for word in words)

    def _regex(self, criteria):
        matches = []
        negative = criteria.get("negative", False)
        for pattern in criteria["regex"]:
            regex = re.compile(pattern)
            if "part" in criteria and criteria["part"].lower() == "header":
                header_values = [value for _, value in header_items(self.response.headers)]
                match = any(regex.search(header_value) for header_value in header_values)
            else:
                match = bool(regex.search(self.response.body))
            matches.append(match)
        condition = criteria.get("condition", "and")
        if condition == "and":
            return not all(matches) if negative else all(matches)
        elif condition == "or":
            return not any(matches) if negative else any(matches)

    def is_match(self, response):
        self.response = response
        matcher_rule = self.rules.get("matcher_rule", {}) or {}
        # Signatures put matchers-condition inside matcher_rule; fall back to the top level for older callers
        matchers_condition = matcher_rule.get("matchers-condition", self.rules.get("matchers-condition", "and"))
        results = []
        for matcher in matcher_rule.get("matchers", []):
            match_type = matcher["type"]
            match_func = getattr(self, f"_{match_type}", None)

            if match_func:
                result = match_func(matcher)
                results.append(result)

        if not results:
            return False
        if matchers_condition == "and":
            return all(results)
        elif matchers_condition == "or":
            return any(results)
        return False
