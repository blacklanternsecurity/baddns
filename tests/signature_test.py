import pytest
from baddns.lib.signature import BadDNSSignature, any_identifier_matches, identifier_matches
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
        sig.initialize(**_make_sig())
        # a matcher-less rule is rejected at load, so set it after initialize to exercise the summary fallback
        sig.signature["matcher_rule"] = {"matchers-condition": "and"}
        summary = sig.summarize_matcher_rule()
        assert summary == "No matchers in signature"


def _rule(*matchers, condition="and"):
    return {"matchers": list(matchers), "matchers-condition": condition}


class TestSignatureMatcherValidation:
    @pytest.mark.parametrize(
        "matcher_rule, message",
        [
            (_rule({"type": "dsl", "dsl": ["Host != ip"]}), "Unsupported matcher type"),
            (_rule({"type": "word", "words": ["x"], "part": "content_type"}), "Unsupported matcher part"),
            (_rule({"type": "word", "words": ["x"], "part": "host"}), "Unsupported matcher part"),
            (_rule({"type": "word", "words": []}), "non-empty"),
            (_rule({"type": "regex", "regex": ["(unclosed"]}), "Invalid regex"),
            (_rule({"type": "status", "status": [404]}), "integer status"),
            (_rule({"type": "word", "words": ["x"], "condition": "xor"}), "Invalid matcher condition"),
            (_rule({"type": "word", "words": ["x"]}, condition="xor"), "Invalid matchers-condition"),
            ({"matchers": [], "matchers-condition": "and"}, "at least one matcher"),
        ],
    )
    def test_rejects_unsupported(self, matcher_rule, message):
        with pytest.raises(BadDNSSignatureException, match=message):
            BadDNSSignature().initialize(**_make_sig(matcher_rule=matcher_rule))

    def test_accepts_supported(self):
        rule = _rule(
            {"type": "word", "words": ["x"], "part": "header", "condition": "or"},
            {"type": "regex", "regex": ["^ok$"], "part": "body"},
            {"type": "status", "status": 404},
            condition="or",
        )
        BadDNSSignature().initialize(**_make_sig(matcher_rule=rule))

    def test_all_shipped_signatures_valid(self):
        from pathlib import Path
        import yaml

        sig_dir = Path(__file__).resolve().parent.parent / "baddns" / "signatures"
        for f in sorted(sig_dir.glob("*.yml")):
            BadDNSSignature().initialize(**yaml.safe_load(f.read_text()))

    def test_all_shipped_signatures_canonical(self):
        """A shipped signature that is not in canonical form makes the SignatureBot re-propose it.

        The bot compares a freshly imported signature against the shipped file byte for byte, so
        whenever the serialized form changes, every shipped file has to be rewritten with it.
        """
        from pathlib import Path
        import yaml

        sig_dir = Path(__file__).resolve().parent.parent / "baddns" / "signatures"
        drifted = []
        for f in sorted(sig_dir.glob("*.yml")):
            candidate = BadDNSSignature()
            candidate.initialize(**yaml.safe_load(f.read_text()))
            if f.read_text() != candidate.canonical_yaml():
                drifted.append(f.name)
        assert not drifted, (
            f"not in canonical form: {', '.join(drifted)}. Run: python3 baddns/scripts/normalize_signatures.py"
        )

    def test_blocked_signatures_are_not_shipped(self):
        """blocked_signatures.txt names signatures we dropped, so none of them may also be shipped."""
        from pathlib import Path

        sig_dir = Path(__file__).resolve().parent.parent / "baddns" / "signatures"
        blocklist = sig_dir / "blocked_signatures.txt"
        blocked = [
            line.strip()
            for line in blocklist.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        assert blocked, "blocked_signatures.txt parsed as empty"
        conflicts = [name for name in blocked if (sig_dir / name).exists()]
        assert not conflicts, f"blocked but still shipped: {', '.join(conflicts)}"


class TestSignatureConfidence:
    def test_confidence_optional_and_not_stored_by_default(self):
        sig = BadDNSSignature()
        sig.initialize(**_make_sig())
        assert "confidence" not in sig.signature

    def test_valid_confidence(self):
        sig = BadDNSSignature()
        sig.initialize(**_make_sig(confidence="MEDIUM"))
        assert sig.signature["confidence"] == "MEDIUM"

    def test_invalid_confidence(self):
        with pytest.raises(BadDNSSignatureException, match="Invalid confidence"):
            BadDNSSignature().initialize(**_make_sig(confidence="POSSIBLE"))


class TestSignatureTlsError:
    def test_tls_error_matcher_valid(self):
        rule = {
            "matchers-condition": "and",
            "matchers": [{"type": "tls_error", "words": ["tlsv1 alert internal error"]}],
        }
        BadDNSSignature().initialize(**_make_sig(matcher_rule=rule))

    def test_tls_error_requires_words(self):
        rule = {"matchers-condition": "and", "matchers": [{"type": "tls_error", "words": []}]}
        with pytest.raises(BadDNSSignatureException, match="tls_error matcher requires"):
            BadDNSSignature().initialize(**_make_sig(matcher_rule=rule))


class TestSignatureIdentifiers:
    def test_regex_identifier_accepted(self):
        sig = BadDNSSignature()
        sig.initialize(**_make_sig(identifiers={"cnames": [{"type": "regex", "value": r"^[a-z0-9-]+\.test\.com$"}]}))
        assert sig.signature["identifiers"]["cnames"] == [{"type": "regex", "value": r"^[a-z0-9-]+\.test\.com$"}]

    @pytest.mark.parametrize("key", ["cnames", "not_cnames", "nameservers"])
    def test_invalid_regex_rejected(self, key):
        with pytest.raises(BadDNSSignatureException, match="Invalid identifier regex"):
            BadDNSSignature().initialize(**_make_sig(identifiers={key: [{"type": "regex", "value": "(unclosed"}]}))

    def test_unsupported_identifier_type_rejected(self):
        with pytest.raises(BadDNSSignatureException, match="Unsupported identifier type"):
            BadDNSSignature().initialize(
                **_make_sig(identifiers={"cnames": [{"type": "glob", "value": "*.test.com"}]})
            )

    @pytest.mark.parametrize("value", [None, "", 404])
    def test_empty_identifier_value_rejected(self, value):
        with pytest.raises(BadDNSSignatureException, match="non-empty string value"):
            BadDNSSignature().initialize(**_make_sig(identifiers={"cnames": [{"type": "word", "value": value}]}))

    def test_non_mapping_identifier_rejected(self):
        with pytest.raises(BadDNSSignatureException, match="must be a string or a mapping"):
            BadDNSSignature().initialize(**_make_sig(identifiers={"cnames": [["test.com"]]}))

    def test_regex_rejected_for_ips(self):
        with pytest.raises(BadDNSSignatureException, match=r"not supported for \[ips\]"):
            BadDNSSignature().initialize(**_make_sig(identifiers={"ips": [{"type": "regex", "value": r"^127\."}]}))

    def test_bare_strings_normalized_to_word(self):
        """dns_nosoa signatures write nameservers as bare strings, and the dnsReaper importer writes IPs
        that way; both must keep loading."""
        sig = BadDNSSignature()
        sig.initialize(
            **_make_sig(
                mode="dns_nosoa",
                matcher_rule=None,
                identifiers={"nameservers": ["ns1.example.com"], "ips": ["127.0.0.1"]},
            )
        )
        assert sig.signature["identifiers"]["nameservers"] == [{"type": "word", "value": "ns1.example.com"}]
        assert sig.signature["identifiers"]["ips"] == [{"type": "word", "value": "127.0.0.1"}]

    def test_type_defaults_to_word(self):
        sig = BadDNSSignature()
        sig.initialize(**_make_sig(identifiers={"cnames": [{"value": "test.com"}]}))
        assert sig.signature["identifiers"]["cnames"] == [{"type": "word", "value": "test.com"}]


class TestIdentifierMatching:
    @pytest.mark.parametrize(
        "identifier, name, mode, expected",
        [
            # word identifiers keep their existing comparison
            ({"type": "word", "value": "test.com"}, "sub.test.com", "suffix", True),
            ({"type": "word", "value": "test.com"}, "test.com.evil.net", "suffix", False),
            ({"type": "word", "value": "test.com"}, "test.com.evil.net", "substring", True),
            # regex is re.search against the whole name, in either mode
            ({"type": "regex", "value": r"^[a-z]+\.test\.com$"}, "sub.test.com", "suffix", True),
            ({"type": "regex", "value": r"^[a-z]+\.test\.com$"}, "a.b.test.com", "suffix", False),
            ({"type": "regex", "value": r"^[a-z]+\.test\.com$"}, "a.b.test.com", "substring", False),
            ({"type": "regex", "value": r"\.test\.com$"}, "a.b.test.com", "substring", True),
        ],
    )
    def test_identifier_matches(self, identifier, name, mode, expected):
        assert identifier_matches(identifier, name, mode=mode) is expected

    def test_any_identifier_matches(self):
        identifiers = [{"type": "word", "value": "nope.com"}, {"type": "regex", "value": r"^good\.com$"}]
        assert any_identifier_matches(identifiers, "good.com") is True
        assert any_identifier_matches(identifiers, "other.com") is False
        assert any_identifier_matches([], "good.com") is False
