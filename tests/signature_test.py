import pytest
from baddns.lib.signature import BadDNSSignature
from baddns.lib.errors import BadDNSSignatureException


def _make_sig(**overrides):
    base = {
        "mode": "http",
        "source": "self",
        "service_name": "TestService",
        "identifiers": {
            "cnames": [{"type": "word", "value": "test.com"}],
            "not_cnames": [],
            "ips": [],
            "nameservers": [],
        },
        "matcher_rule": {
            "matchers": [{"type": "word", "words": ["Not Found"], "part": "body", "condition": "and"}],
            "matchers-condition": "and",
        },
    }
    base.update(overrides)
    return base


class TestSignatureInitialize:
    def test_valid_http_signature(self):
        sig = BadDNSSignature()
        sig.initialize(**_make_sig())
        assert sig.signature["service_name"] == "TestService"

    def test_missing_mode(self):
        with pytest.raises(BadDNSSignatureException, match="mode is a required attribute"):
            sig = BadDNSSignature()
            sig.initialize(**_make_sig(mode=None))

    def test_invalid_mode(self):
        with pytest.raises(BadDNSSignatureException, match="not a valid mode"):
            sig = BadDNSSignature()
            sig.initialize(**_make_sig(mode="invalid"))

    def test_missing_source(self):
        with pytest.raises(BadDNSSignatureException, match="source is a required attribute"):
            sig = BadDNSSignature()
            sig.initialize(**_make_sig(source=None))

    def test_invalid_source(self):
        with pytest.raises(BadDNSSignatureException, match="not a valid mode"):
            sig = BadDNSSignature()
            sig.initialize(**_make_sig(source="invalid"))

    def test_missing_service_name(self):
        with pytest.raises(BadDNSSignatureException, match="service_name is a required attribute"):
            sig = BadDNSSignature()
            sig.initialize(**_make_sig(service_name=None))

    def test_http_without_matcher_rule(self):
        with pytest.raises(BadDNSSignatureException, match="http mode requires a matcher_rule entry"):
            sig = BadDNSSignature()
            sig.initialize(**_make_sig(matcher_rule=None))

    def test_dns_nxdomain_with_matcher_rule(self):
        with pytest.raises(BadDNSSignatureException, match="matcher_rule should not be set"):
            sig = BadDNSSignature()
            sig.initialize(**_make_sig(mode="dns_nxdomain", matcher_rule={"matchers": []}))

    def test_dns_nosoa_without_nameservers(self):
        with pytest.raises(BadDNSSignatureException, match="nameservers are required"):
            sig = BadDNSSignature()
            sig.initialize(**_make_sig(mode="dns_nosoa", matcher_rule=None))

    def test_valid_dns_nxdomain(self):
        sig = BadDNSSignature()
        sig.initialize(**_make_sig(mode="dns_nxdomain", matcher_rule=None))
        assert sig.signature["mode"] == "dns_nxdomain"

    def test_valid_dns_nosoa(self):
        sig = BadDNSSignature()
        sig.initialize(
            **_make_sig(
                mode="dns_nosoa",
                matcher_rule=None,
                identifiers={"cnames": [], "not_cnames": [], "ips": [], "nameservers": ["ns1.example.com"]},
            )
        )
        assert sig.signature["mode"] == "dns_nosoa"


class TestSignatureOutput:
    def test_output(self):
        sig = BadDNSSignature()
        sig.initialize(**_make_sig())
        out = sig.output()
        assert out["service_name"] == "TestService"
        assert out["mode"] == "http"

    def test_summarize_matcher_rule(self):
        sig = BadDNSSignature()
        sig.initialize(**_make_sig())
        summary = sig.summarize_matcher_rule()
        assert "Not Found" in summary
        assert "Matchers-Condition: and" in summary

    def test_summarize_no_matchers(self):
        sig = BadDNSSignature()
        sig.initialize(**_make_sig(matcher_rule={"matchers-condition": "and"}))
        summary = sig.summarize_matcher_rule()
        assert summary == "No matchers in signature"
