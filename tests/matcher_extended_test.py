import pytest
import httpx
from baddns.lib.matcher import Matcher


class TestMatcherInit:
    def test_yaml_string(self):
        yaml_str = """
matchers-condition: and
matcher_rule:
  matchers:
  - type: word
    words: ["test"]
    part: body
"""
        m = Matcher(yaml_str)
        assert "matchers-condition" in m.rules

    def test_yaml_parse_error(self):
        with pytest.raises(ValueError, match="Error parsing YAML"):
            Matcher("{{invalid: yaml: [")

    def test_dict_input(self):
        m = Matcher({"matchers-condition": "and", "matcher_rule": {"matchers": []}})
        assert m.rules["matchers-condition"] == "and"

    def test_invalid_type(self):
        with pytest.raises(TypeError, match="yaml_rules must be a YAML string or a dict"):
            Matcher(12345)


class TestMatcherStatus:
    def test_status_negative(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=200)
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "status", "status": 200, "negative": True}]},
        }
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        assert not m.is_match(r)

    def test_status_negative_nonmatch(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=404)
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "status", "status": 200, "negative": True}]},
        }
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        assert m.is_match(r)


class TestMatcherWord:
    def test_word_host_part(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=200, text="body")
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "word", "words": ["test"], "part": "host"}]},
        }
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        assert m.is_match(r)

    def test_word_cname_part(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=200, text="body")
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "word", "words": ["test"], "part": "cname"}]},
        }
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        assert m.is_match(r)

    def test_word_unknown_part(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=200, text="body")
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "word", "words": ["test"], "part": "unknown"}]},
        }
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        with pytest.raises(ValueError, match="Unknown part"):
            m.is_match(r)

    def test_word_negative_and(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=200, text="hello world")
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {
                "matchers": [
                    {"type": "word", "words": ["hello", "world"], "part": "body", "condition": "and", "negative": True}
                ]
            },
        }
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        assert not m.is_match(r)

    def test_word_negative_or(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=200, text="hello world")
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {
                "matchers": [
                    {"type": "word", "words": ["hello", "xyz"], "part": "body", "condition": "or", "negative": True}
                ]
            },
        }
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        assert not m.is_match(r)

    def test_word_or_condition(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=200, text="hello world")
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {
                "matchers": [{"type": "word", "words": ["hello", "notfound"], "part": "body", "condition": "or"}]
            },
        }
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        assert m.is_match(r)


class TestMatcherRegex:
    def test_regex_header(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=200, text="", headers={"X-Custom": "abc123def"})
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "regex", "regex": ["abc\\d+def"], "part": "header"}]},
        }
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        assert m.is_match(r)

    def test_regex_negative(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=200, text="abc123def")
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "regex", "regex": ["abc\\d+def"], "negative": True}]},
        }
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        assert not m.is_match(r)

    def test_regex_or_condition(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=200, text="hello world")
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "regex", "regex": ["nomatch", "hello"], "condition": "or"}]},
        }
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        assert m.is_match(r)

    def test_regex_negative_or(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=200, text="hello world")
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {
                "matchers": [{"type": "regex", "regex": ["hello", "nomatch"], "condition": "or", "negative": True}]
            },
        }
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        assert not m.is_match(r)


class TestMatcherIsMatch:
    def test_invalid_response_type(self):
        m = Matcher({"matchers-condition": "and", "matcher_rule": {"matchers": []}})
        with pytest.raises(TypeError, match="response must be an httpx.Response"):
            m.is_match("not a response")

    def test_or_matchers_condition(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=200, text="hello")
        rules = {
            "matchers-condition": "or",
            "matcher_rule": {
                "matchers": [
                    {"type": "status", "status": 404},
                    {"type": "word", "words": ["hello"], "part": "body"},
                ]
            },
        }
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        assert m.is_match(r)

    def test_no_matching_func(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=200, text="hello")
        rules = {
            "matchers-condition": "and",
            "matcher_rule": {"matchers": [{"type": "dsl", "dsl": ["Host != ip"]}]},
        }
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        # dsl type has no handler, results empty, all([]) is True
        assert m.is_match(r)

    def test_empty_matchers(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=200, text="hello")
        rules = {"matchers-condition": "and", "matcher_rule": {"matchers": []}}
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        assert m.is_match(r)

    def test_unknown_matchers_condition(self, httpx_mock):
        httpx_mock.add_response(url="https://test.com/", status_code=200, text="hello")
        rules = {
            "matchers-condition": "xor",
            "matcher_rule": {"matchers": [{"type": "word", "words": ["hello"], "part": "body"}]},
        }
        m = Matcher(rules)
        r = httpx.get("https://test.com/")
        assert not m.is_match(r)
