import re
import os
import sys
import requests
import yaml

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from lib.errors import BadDNSMatcherException


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
        return self.response.status_code in criteria["status"]

    def _word(self, criteria):
        words = criteria["words"]
        part = criteria.get("part", "body").lower()

        if part == "header":
            text = str(self.response.headers)
        elif part == "body":
            text = self.response.text
        else:
            raise ValueError(f"Unknown part: {part}")

        condition = criteria.get("condition", "and")
        if condition == "and":
            return all(word in text for word in words)
        elif condition == "or":
            return any(word in text for word in words)

    def _regex(self, matcher):
        matches = []
        for pattern in matcher["regex"]:
            regex = re.compile(pattern)
            if "part" in matcher and matcher["part"].lower() == "header":
                match = any(regex.search(header_value) for header_value in self.response.headers.values())
            else:
                match = bool(regex.search(self.response.text))
            matches.append(match)
        return all(matches) if matcher.get("condition", "and") == "and" else any(matches)

    def is_match(self, response):
        if not isinstance(response, requests.models.Response):
            raise TypeError("response must be a requests.Response object")
        self.response = response

        matchers_condition = self.rules.get("matchers-condition", "and")
        results = []
        for matcher in self.rules.get("matchers", []):
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
