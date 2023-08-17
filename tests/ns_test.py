import pytest

from baddns.lib.baddns import BadDNS_ns
from .helpers import MockResolver, mock_signature_load


@pytest.mark.asyncio
async def test_ns_nosoa_signature(fs):
    mock_data = {"bad.dns": {"NS": ["ns1.wordpress.com."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}

    mock_resolver = MockResolver(mock_data)

    target = "bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")

    baddns_ns = BadDNS_ns(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)

    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert findings
    assert {
        "target": "bad.dns",
        "nameservers": ["ns1.wordpress.com."],
        "signature_name": "wordpress.com",
        "matching_signatures": ["ns1.wordpress.com"],
        "technique": "NS RECORD WITHOUT SOA",
    } in findings


@pytest.mark.asyncio
async def test_ns_nosoa_generic(fs):
    mock_data = {"bad.dns": {"NS": ["ns1.somerandomthing.com."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}

    mock_resolver = MockResolver(mock_data)

    target = "bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")

    baddns_ns = BadDNS_ns(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)

    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert findings
    assert {
        "target": "bad.dns",
        "nameservers": ["ns1.somerandomthing.com."],
        "signature_name": "GENERIC",
        "matching_signatures": None,
        "technique": "NS RECORD WITHOUT SOA",
    } in findings
