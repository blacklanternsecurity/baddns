import re
import os
import sys
import httpx
import yaml
import logging

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
        return (
            self.response.status_code != criteria["status"]
            if negative
            else self.response.status_code == criteria["status"]
        )

    def _word(self, criteria):
        words = criteria["words"]
        part = criteria.get("part", "body").lower()
        negative = criteria.get("negative", False)

        if part == "header":
            text = str(self.response.headers)
        elif part == "body":
            text = self.response.text

        # we can ignore this because are already adding these entries into the identifiers
        elif part == "host":
            return True
        else:
            raise ValueError(f"Unknown part: {part}")

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
                match = any(regex.search(header_value) for header_value in self.response.headers.values())
            else:
                match = bool(regex.search(self.response.text))
            matches.append(match)
        condition = criteria.get("condition", "and")
        if condition == "and":
            return not all(matches) if negative else all(matches)
        elif condition == "or":
            return not any(matches) if negative else any(matches)

    def is_match(self, response):
        if not isinstance(response, httpx.Response):
            raise TypeError("response must be an httpx.Response object")
        self.response = response
        matchers_condition = self.rules.get("matchers-condition", "and")
        results = []
        matcher_rule = self.rules.get("matcher_rule", {})
        for matcher in matcher_rule.get("matchers", []):
            match_type = matcher["type"]
            match_func = getattr(self, f"_{match_type}", None)

            if match_func:
                result = match_func(matcher)
                results.append(result)

        if matchers_condition == "and":
            return all(results)
        elif matchers_condition == "or":
            return any(results)
        return False
