import pytest

from baddns.modules.ns import BadDNS_ns
from .helpers import mock_signature_load
import functools
import requests

requests.adapters.BaseAdapter.send = functools.partialmethod(requests.adapters.BaseAdapter.send, verify=False)
requests.adapters.HTTPAdapter.send = functools.partialmethod(requests.adapters.HTTPAdapter.send, verify=False)
requests.Session.request = functools.partialmethod(requests.Session.request, verify=False)
requests.request = functools.partial(requests.request, verify=False)


@pytest.mark.asyncio
async def test_ns_nosoa_signature(fs, configure_mock_resolver):
    mock_data = {"bad.dns": {"NS": ["ns1.wordpress.com."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=["ns1.wordpress.com"])

    target = "bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")

    baddns_ns = BadDNS_ns(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)
    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling NS Records (NS records without SOA) with known impact",
        "confidence": "PROBABLE",
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

    baddns_ns = BadDNS_ns(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)

    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling NS Records (NS records without SOA)",
        "confidence": "POSSIBLE",
        "signature": "N/A",
        "indicator": "DNSWalk Analysis",
        "trigger": "ns1.somerandomthing.com",
        "module": "NS",
    }
    assert any(expected == finding.to_dict() for finding in findings)
