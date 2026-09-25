import re
import os
import sys
import yaml
import logging

from baddns.lib.httpmanager import headers_to_dict
from baddns.lib.yara_helper import YaraHelper

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

log = logging.getLogger(__name__)

_yara_helper = YaraHelper()


class WordMatcher:
    """Batch all word matchers across signatures into a single YARA ruleset.

    Compile once at signature load time, match once per response body/headers.
    """

    def __init__(self, signatures):
        self._body_rules = []
        self._header_rules = []
        body_yara_src = []
        header_yara_src = []

        for sig_idx, sig in enumerate(signatures):
            mr = sig.signature.get("matcher_rule") or {}
            for matcher_idx, matcher in enumerate(mr.get("matchers", [])):
                if matcher.get("type") != "word":
                    continue
                part = matcher.get("part", "body").lower()
                if part in ("host", "cname"):
                    continue

                words = matcher["words"]
                condition = matcher.get("condition", "and")
                negative = matcher.get("negative", False)
                rule_name = f"sig_{sig_idx}_m_{matcher_idx}"

                yara_strings = []
                for j, w in enumerate(words):
                    w_esc = (
                        w.replace("\\", "\\\\")
                        .replace('"', '\\"')
                        .replace("\n", "\\n")
                        .replace("\r", "\\r")
                        .replace("\t", "\\t")
                    )
                    yara_strings.append(f'        $s{j} = "{w_esc}"')

                yara_cond = "all of them" if condition == "and" else "any of them"
                rule_src = (
                    f"rule {rule_name} {{\n"
                    f"    strings:\n" + "\n".join(yara_strings) + "\n"
                    f"    condition:\n"
                    f"        {yara_cond}\n"
                    f"}}"
                )

                entry = {
                    "sig_idx": sig_idx,
                    "matcher_idx": matcher_idx,
                    "rule_name": rule_name,
                    "negative": negative,
                }

                if part == "header":
                    self._header_rules.append(entry)
                    header_yara_src.append(rule_src)
                else:
                    self._body_rules.append(entry)
                    body_yara_src.append(rule_src)

        self._compiled_body = _yara_helper.compile(source="\n".join(body_yara_src)) if body_yara_src else None
        self._compiled_header = _yara_helper.compile(source="\n".join(header_yara_src)) if header_yara_src else None

    def match(self, response):
        """Return dict of (sig_idx, matcher_idx) -> bool for all word matchers."""
        results = {}

        if self._compiled_body and response.body:
            self._eval_rules(self._compiled_body, self._body_rules, response.body, results)

        if self._compiled_header and response.headers:
            header_text = str(headers_to_dict(response.headers))
            self._eval_rules(self._compiled_header, self._header_rules, header_text, results)

        return results

    def _eval_rules(self, compiled, rules, text, results):
        if isinstance(text, str):
            text_bytes = text.encode("utf-8", errors="replace")
        else:
            text_bytes = text
        matches = compiled.match(data=text_bytes)
        hit_rules = {m.rule for m in matches}

        for entry in rules:
            key = (entry["sig_idx"], entry["matcher_idx"])
            hit = entry["rule_name"] in hit_rules
            if entry["negative"]:
                hit = not hit
            results[key] = hit


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

    def _word(self, criteria):
        words = criteria["words"]
        part = criteria.get("part", "body").lower()
        negative = criteria.get("negative", False)

        if part == "header":
            text = str(headers_to_dict(self.response.headers))
        elif part == "body":
            text = self.response.body

        # we can ignore this because are already adding these entries into the identifiers
        elif part in ("host", "cname"):
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
                header_values = headers_to_dict(self.response.headers).values()
                match = any(regex.search(header_value) for header_value in header_values)
            else:
                match = bool(regex.search(self.response.body))
            matches.append(match)
        condition = criteria.get("condition", "and")
        if condition == "and":
            return not all(matches) if negative else all(matches)
        elif condition == "or":
            return not any(matches) if negative else any(matches)

    def is_match(self, response, word_results=None, sig_idx=None):
        self.response = response
        matchers_condition = self.rules.get("matchers-condition", "and")
        results = []
        matcher_rule = self.rules.get("matcher_rule", {})
        for matcher_idx, matcher in enumerate(matcher_rule.get("matchers", [])):
            match_type = matcher["type"]
            if match_type == "word" and word_results is not None and sig_idx is not None:
                key = (sig_idx, matcher_idx)
                part = matcher.get("part", "body").lower()
                if part in ("host", "cname"):
                    results.append(True)
                elif key in word_results:
                    results.append(word_results[key])
                else:
                    results.append(False)
                continue
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
