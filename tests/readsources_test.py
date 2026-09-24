import os

import yaml

from baddns.scripts import readsources
from baddns.scripts.readsources import DnsReaperSignatureTransformer, NucleiTemplatesTransformer


def _nuclei_http(matchers, condition="and", name="Test Takeover"):
    return {
        "info": {"name": name},
        "http": [{"path": ["{{BaseURL}}"], "matchers-condition": condition, "matchers": matchers}],
    }


def test_dsl_host_noop_dropped_silently():
    t = NucleiTemplatesTransformer(
        _nuclei_http([{"type": "dsl", "dsl": ["Host != ip"]}, {"type": "word", "words": ["gone"]}])
    )
    values = t.map_values()
    assert [m["type"] for m in values["matcher_rule"]["matchers"]] == ["word"]
    assert t.notes == []


def test_dsl_contains_cname_becomes_identifier():
    t = NucleiTemplatesTransformer(
        _nuclei_http(
            [{"type": "dsl", "dsl": ['contains(cname, ".azurewebsites.net")']}, {"type": "word", "words": ["x"]}]
        )
    )
    assert t.map_values()["identifiers"]["cnames"] == [{"type": "word", "value": "azurewebsites.net"}]


def test_host_exclusion_is_dropped_not_inverted():
    """Regression: '!contains(host,...)' and negative host words used to become required or excluded CNAMEs."""
    t = NucleiTemplatesTransformer(
        _nuclei_http(
            [
                {"type": "dsl", "dsl": ['!contains(host,".wix.com")']},
                {"type": "word", "part": "host", "words": ["amazonaws.com"], "negative": True},
                {"type": "word", "words": ["The specified bucket does not exist"]},
            ]
        )
    )
    values = t.map_values()
    assert values["identifiers"]["cnames"] == []
    assert values["identifiers"]["not_cnames"] == []
    assert any("wix.com" in n for n in t.notes)
    assert any("amazonaws.com" in n for n in t.notes)


def test_nuclei_defaults_to_or_conditions():
    t = NucleiTemplatesTransformer(
        {"info": {"name": "x"}, "http": [{"matchers": [{"type": "word", "words": ["a", "b"]}]}]}
    )
    rule = t.map_values()["matcher_rule"]
    assert rule["matchers-condition"] == "or"
    assert rule["matchers"][0]["condition"] == "or"


def test_content_type_becomes_header_word():
    t = NucleiTemplatesTransformer(_nuclei_http([{"type": "word", "part": "content_type", "words": ["text/plain"]}]))
    matcher = t.map_values()["matcher_rule"]["matchers"][0]
    assert matcher == {"type": "word", "part": "header", "words": ["content-type: text/plain"], "condition": "or"}


def test_extra_statuses_noted():
    t = NucleiTemplatesTransformer(_nuclei_http([{"type": "status", "status": [404, 410]}]))
    assert t.map_values()["matcher_rule"]["matchers"][0] == {"type": "status", "status": 404}
    assert any("404, 410" in n for n in t.notes)


def test_dnsreaper_code_zero_dropped():
    source = """
from .templates.cname_found_but_status_code import cname_found_but_status_code

test = cname_found_but_status_code(
    cname="cname.helpscoutdocs.com",
    code=0,
    service="helpscoutdocs.com",
)
"""
    t = DnsReaperSignatureTransformer(source)
    values = t.map_values()
    assert "matcher_rule" not in values
    assert any("code=0" in n for n in t.notes)


def test_dnsreaper_cname_prefix_only_stripped():
    source = """
test = cname_found_but_string_in_body(
    cname=["cname.short.io", ".foo-cname.example.com"],
    domain_not_configured_message="gone",
    service="x",
)
"""
    values = DnsReaperSignatureTransformer(source).map_values()
    assert [c["value"] for c in values["identifiers"]["cnames"]] == ["short.io", "foo-cname.example.com"]


def test_write_signature_validates_before_writing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    os.makedirs(readsources.OUTPUT_DIRECTORY)
    bad = {
        "service_name": "x",
        "source": "nucleitemplates",
        "mode": "http",
        "identifiers": {},
        "matcher_rule": {"matchers": []},
    }
    assert not readsources.write_signature("nucleitemplates", "bad", bad, [])
    assert not (tmp_path / readsources.OUTPUT_DIRECTORY / "nucleitemplates_bad.yml").exists()

    good = dict(bad, matcher_rule={"matchers-condition": "or", "matchers": [{"type": "word", "words": ["x"]}]})
    assert readsources.write_signature("nucleitemplates", "good", good, ["dropped something"])
    written = yaml.safe_load((tmp_path / readsources.OUTPUT_DIRECTORY / "nucleitemplates_good.yml").read_text())
    assert "negative_signature" not in written
    assert (
        tmp_path / readsources.OUTPUT_DIRECTORY / "nucleitemplates_good.notes"
    ).read_text() == "- dropped something\n"
