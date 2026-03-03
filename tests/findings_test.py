import pytest
from baddns.lib.findings import Finding
from baddns.lib.errors import BadDNSFindingException
from baddns.modules.cname import BadDNS_cname


def _valid_finding(**overrides):
    base = {
        "target": "bad.dns",
        "description": "test finding",
        "confidence": "CONFIRMED",
        "severity": "MEDIUM",
        "signature": "TestSig",
        "indicator": "test indicator",
        "trigger": "test.trigger.com",
        "module": BadDNS_cname,
    }
    base.update(overrides)
    return base


class TestFindingValidation:
    def test_missing_target(self):
        with pytest.raises(BadDNSFindingException, match="Target is required"):
            Finding(_valid_finding(target=None))

    def test_non_str_description(self):
        with pytest.raises(BadDNSFindingException, match="description field must be a str"):
            Finding(_valid_finding(description=123))

    def test_invalid_confidence(self):
        with pytest.raises(BadDNSFindingException, match="Confidence must be present"):
            Finding(_valid_finding(confidence="INVALID"))

    def test_missing_confidence(self):
        with pytest.raises(BadDNSFindingException, match="Confidence must be present"):
            Finding(_valid_finding(confidence=None))

    def test_invalid_severity(self):
        with pytest.raises(BadDNSFindingException, match="Severity must be present"):
            Finding(_valid_finding(severity="INVALID"))

    def test_missing_severity(self):
        with pytest.raises(BadDNSFindingException, match="Severity must be present"):
            Finding(_valid_finding(severity=None))

    def test_missing_signature(self):
        with pytest.raises(BadDNSFindingException, match="signature is required"):
            Finding(_valid_finding(signature=None))

    def test_missing_indicator(self):
        with pytest.raises(BadDNSFindingException, match="indicator is required"):
            Finding(_valid_finding(indicator=None))

    def test_missing_trigger(self):
        with pytest.raises(BadDNSFindingException, match="trigger is required"):
            Finding(_valid_finding(trigger=None))

    def test_trigger_invalid_type(self):
        with pytest.raises(BadDNSFindingException, match="trigger must be either str or list"):
            Finding(_valid_finding(trigger=12345))

    def test_missing_module(self):
        with pytest.raises(BadDNSFindingException, match="Module is required"):
            Finding(_valid_finding(module=None))

    def test_invalid_module(self):
        with pytest.raises(BadDNSFindingException, match="Module was not a valid baddns module"):
            Finding(_valid_finding(module=str))


class TestFindingOutput:
    def test_valid_finding(self):
        f = Finding(_valid_finding())
        d = f.to_dict()
        assert d["target"] == "bad.dns"
        assert d["confidence"] == "CONFIRMED"
        assert d["severity"] == "MEDIUM"
        assert d["module"] == "CNAME"

    def test_trigger_list(self):
        f = Finding(_valid_finding(trigger=["a.com", "b.com"]))
        assert f.to_dict()["trigger"] == "a.com, b.com"

    def test_trigger_string(self):
        f = Finding(_valid_finding(trigger="single.com"))
        assert f.to_dict()["trigger"] == "single.com"

    def test_to_json(self):
        f = Finding(_valid_finding())
        j = f.to_json()
        assert '"target": "bad.dns"' in j

    def test_str(self):
        f = Finding(_valid_finding())
        assert "bad.dns" in str(f)

    def test_found_domains(self):
        f = Finding(_valid_finding(found_domains=["a.example.com", "b.example.com"]))
        assert f.to_dict()["found_domains"] == ["a.example.com", "b.example.com"]

    def test_default_description(self):
        d = _valid_finding()
        del d["description"]
        f = Finding(d)
        assert f.to_dict()["description"] == "N/A"

    def test_name_with_signature(self):
        f = Finding(_valid_finding(signature="Azure Takeover"))
        assert f.name == "BadDNS CNAME Azure Takeover"

    def test_name_without_signature(self):
        f = Finding(_valid_finding(signature="N/A"))
        assert f.name == "BadDNS CNAME"


class TestMeetsMinimum:
    def test_no_filters(self):
        f = Finding(_valid_finding(confidence="LOW", severity="INFORMATIONAL"))
        assert f.meets_minimum() is True

    def test_confidence_exact_match(self):
        f = Finding(_valid_finding(confidence="HIGH"))
        assert f.meets_minimum(min_confidence="HIGH") is True

    def test_confidence_above_threshold(self):
        f = Finding(_valid_finding(confidence="CONFIRMED"))
        assert f.meets_minimum(min_confidence="HIGH") is True

    def test_confidence_below_threshold(self):
        f = Finding(_valid_finding(confidence="LOW"))
        assert f.meets_minimum(min_confidence="HIGH") is False

    def test_severity_exact_match(self):
        f = Finding(_valid_finding(severity="MEDIUM"))
        assert f.meets_minimum(min_severity="MEDIUM") is True

    def test_severity_above_threshold(self):
        f = Finding(_valid_finding(severity="CRITICAL"))
        assert f.meets_minimum(min_severity="LOW") is True

    def test_severity_below_threshold(self):
        f = Finding(_valid_finding(severity="INFORMATIONAL"))
        assert f.meets_minimum(min_severity="LOW") is False

    def test_both_filters_pass(self):
        f = Finding(_valid_finding(confidence="CONFIRMED", severity="CRITICAL"))
        assert f.meets_minimum(min_confidence="HIGH", min_severity="MEDIUM") is True

    def test_confidence_passes_severity_fails(self):
        f = Finding(_valid_finding(confidence="CONFIRMED", severity="INFORMATIONAL"))
        assert f.meets_minimum(min_confidence="HIGH", min_severity="MEDIUM") is False

    def test_confidence_fails_severity_passes(self):
        f = Finding(_valid_finding(confidence="UNKNOWN", severity="CRITICAL"))
        assert f.meets_minimum(min_confidence="HIGH", min_severity="MEDIUM") is False
