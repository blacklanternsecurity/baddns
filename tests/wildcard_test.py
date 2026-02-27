import functools
import pytest
import requests
import ssl
from baddns.modules.wildcard import BadDNS_wildcard
from baddns.lib.loader import load_signatures
from .helpers import mock_signature_load

ssl._create_default_https_context = ssl._create_unverified_context

requests.adapters.BaseAdapter.send = functools.partialmethod(requests.adapters.BaseAdapter.send, verify=False)
requests.adapters.HTTPAdapter.send = functools.partialmethod(requests.adapters.HTTPAdapter.send, verify=False)
requests.Session.request = functools.partialmethod(requests.Session.request, verify=False)
requests.request = functools.partial(requests.request, verify=False)


@pytest.fixture(autouse=True)
def patch_random_label(monkeypatch):
    monkeypatch.setattr(BadDNS_wildcard, "_generate_random_label", staticmethod(lambda: "baddns-test1234"))


@pytest.mark.asyncio
async def test_wildcard_cname_nxdomain_signature_match(fs, mock_dispatch_whois, configure_mock_resolver):
    """Wildcard CNAME to NXDOMAIN service with signature match -> HIGH severity finding."""
    mock_data = {
        "baddns-test1234.bad.dns": {"CNAME": ["baddns.azurewebsites.net."]},
        "_NXDOMAIN": ["baddns.azurewebsites.net"],
    }
    mock_resolver = configure_mock_resolver(mock_data)

    target = "sub.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_wildcard.dispatch():
        findings = baddns_wildcard.analyze()

    assert findings
    expected = {
        "target": "sub.bad.dns",
        "description": "Wildcard CNAME detected at *.bad.dns. ALL subdomains of bad.dns are affected. Original Event: [Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)]",
        "confidence": "HIGH",
        "severity": "HIGH",
        "signature": "Microsoft Azure Takeover Detection",
        "indicator": "azurewebsites.net",
        "trigger": "*.bad.dns",
        "module": "WILDCARD",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_wildcard_no_wildcard_nxdomain(fs, mock_dispatch_whois, configure_mock_resolver):
    """No wildcard record (NXDOMAIN for random subdomain) -> dispatch returns False."""
    mock_data = {
        "_NXDOMAIN": ["baddns-test1234.bad.dns"],
    }
    mock_resolver = configure_mock_resolver(mock_data)

    target = "sub.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver)

    result = await baddns_wildcard.dispatch()
    assert result is False


@pytest.mark.asyncio
async def test_wildcard_a_record_only(fs, mock_dispatch_whois, configure_mock_resolver):
    """Wildcard resolves to A record only (no CNAME) -> dispatch returns False."""
    mock_data = {
        "baddns-test1234.bad.dns": {"A": ["1.2.3.4"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)

    target = "sub.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver)

    result = await baddns_wildcard.dispatch()
    assert result is False


@pytest.mark.asyncio
async def test_wildcard_target_is_registered_domain(fs, mock_dispatch_whois, configure_mock_resolver):
    """Target is already a registered domain (e.g. bad.dns) -> dispatch returns False."""
    mock_data = {}
    mock_resolver = configure_mock_resolver(mock_data)

    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver)

    result = await baddns_wildcard.dispatch()
    assert result is False


@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
async def test_wildcard_cname_resolves_not_vulnerable(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    """Wildcard CNAME resolves to a healthy target -> no findings."""
    mock_data = {
        "baddns-test1234.bad.dns": {"CNAME": ["healthy.example.com."]},
        "healthy.example.com": {"A": ["1.2.3.4"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)

    target = "sub.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_wildcard.dispatch():
        findings = baddns_wildcard.analyze()

    assert not findings


@pytest.mark.asyncio
async def test_wildcard_deep_subdomain(fs, mock_dispatch_whois, configure_mock_resolver):
    """Deep subdomain (deep.sub.bad.dns) checks *.sub.bad.dns."""
    mock_data = {
        "baddns-test1234.sub.bad.dns": {"CNAME": ["baddns.azurewebsites.net."]},
        "_NXDOMAIN": ["baddns.azurewebsites.net"],
    }
    mock_resolver = configure_mock_resolver(mock_data)

    target = "deep.sub.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_wildcard.dispatch():
        findings = baddns_wildcard.analyze()

    assert findings
    expected = {
        "target": "deep.sub.bad.dns",
        "description": "Wildcard CNAME detected at *.sub.bad.dns. ALL subdomains of sub.bad.dns are affected. Original Event: [Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)]",
        "confidence": "HIGH",
        "severity": "HIGH",
        "signature": "Microsoft Azure Takeover Detection",
        "indicator": "azurewebsites.net",
        "trigger": "*.sub.bad.dns",
        "module": "WILDCARD",
    }
    assert any(expected == finding.to_dict() for finding in findings)


mock_whois_unregistered = {
    "type": "error",
    "data": 'No match for "WORSE.DNS".\r\n>>> Last update of whois database: 2023-08-17T14:07:31Z <<<\r\n',
}


@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_unregistered], indirect=True)
async def test_wildcard_whois_unregistered(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    """Wildcard CNAME to a domain that is unregistered per WHOIS -> CONFIRMED confidence."""
    mock_data = {
        "baddns-test1234.bad.dns": {"CNAME": ["worse.dns."]},
        "worse.dns": {"A": ["127.0.0.2"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)

    target = "sub.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_wildcard.dispatch():
        findings = baddns_wildcard.analyze()

    assert findings
    assert any(f.to_dict()["confidence"] == "CONFIRMED" for f in findings)
    assert any(f.to_dict()["severity"] == "HIGH" for f in findings)
    assert any(f.to_dict()["module"] == "WILDCARD" for f in findings)


@pytest.mark.asyncio
async def test_wildcard_generic_dangling_cname(fs, mock_dispatch_whois, configure_mock_resolver):
    """Wildcard CNAME to unknown NXDOMAIN service (no signature) -> MODERATE confidence, GENERIC."""
    mock_data = {
        "baddns-test1234.bad.dns": {"CNAME": ["unknown.randomthing.net."]},
        "_NXDOMAIN": ["unknown.randomthing.net"],
    }
    mock_resolver = configure_mock_resolver(mock_data)

    target = "sub.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_wildcard.dispatch():
        findings = baddns_wildcard.analyze()

    assert findings
    expected = {
        "target": "sub.bad.dns",
        "description": "Wildcard CNAME detected at *.bad.dns. ALL subdomains of bad.dns are affected. Original Event: [Dangling CNAME, possible subdomain takeover (NXDOMAIN technique)]",
        "confidence": "MODERATE",
        "severity": "HIGH",
        "signature": "GENERIC",
        "indicator": "Generic Dangling CNAME",
        "trigger": "*.bad.dns",
        "module": "WILDCARD",
    }
    assert any(expected == finding.to_dict() for finding in findings)
