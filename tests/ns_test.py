import pytest

from baddns.modules.ns import BadDNS_ns
from baddns.lib.loader import load_signatures
from .helpers import mock_signature_load


@pytest.mark.asyncio
async def test_ns_nosoa_signature(fs, configure_mock_resolver):
    mock_data = {"bad.dns": {"NS": ["ns1.wordpress.com."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=["ns1.wordpress.com"])

    target = "bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns(target, signatures=signatures, dns_client=mock_resolver)
    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling NS Records (NS records without SOA) with known impact",
        "confidence": "HIGH",
        "severity": "MEDIUM",
        "signature": "wordpress.com",
        "indicator": "DnsWalk Analysis with signature match: ['ns1.wordpress.com']",
        "trigger": "ns1.wordpress.com",
        "module": "NS",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_ns_nosoa_generic(fs, configure_mock_resolver):
    mock_data = {"bad.dns": {"NS": ["ns1.somerandomthing.com."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=["ns1.somerandomthing.com"])

    target = "bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling NS Records (NS records without SOA)",
        "confidence": "LOW",
        "severity": "MEDIUM",
        "signature": "GENERIC",
        "indicator": "DNSWalk Analysis",
        "trigger": "ns1.somerandomthing.com",
        "module": "NS",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_ns_nosoa_negative_signature(fs, configure_mock_resolver):
    mock_data = {"bad.dns": {"NS": ["pdns1.ultradns.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=["pdns1.ultradns.net"])

    target = "bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")
    mock_signature_load(fs, "negative_ultradns_ns.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert not findings


@pytest.mark.asyncio
async def test_ns_nosoa_positive_with_negative_loaded(fs, configure_mock_resolver):
    """Positive signature still fires when negative signatures are also loaded."""
    mock_data = {"bad.dns": {"NS": ["ns1.wordpress.com."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=["ns1.wordpress.com"])

    target = "bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")
    mock_signature_load(fs, "negative_ultradns_ns.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling NS Records (NS records without SOA) with known impact",
        "confidence": "HIGH",
        "severity": "MEDIUM",
        "signature": "wordpress.com",
        "indicator": "DnsWalk Analysis with signature match: ['ns1.wordpress.com']",
        "trigger": "ns1.wordpress.com",
        "module": "NS",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_ns_nosoa_generic_with_negative_loaded(fs, configure_mock_resolver):
    """Generic finding still fires when negative signatures are loaded but don't match."""
    mock_data = {"bad.dns": {"NS": ["ns1.somerandomthing.com."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=["ns1.somerandomthing.com"])

    target = "bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")
    mock_signature_load(fs, "negative_ultradns_ns.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling NS Records (NS records without SOA)",
        "confidence": "LOW",
        "severity": "MEDIUM",
        "signature": "GENERIC",
        "indicator": "DNSWalk Analysis",
        "trigger": "ns1.somerandomthing.com",
        "module": "NS",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_ns_label_too_long(fs, configure_mock_resolver):
    mock_data = {}
    mock_resolver = configure_mock_resolver(mock_data)

    target = "a" * 64 + ".bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert not findings
