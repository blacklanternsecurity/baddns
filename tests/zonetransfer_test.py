import pytest
import dns


from baddns.modules.zonetransfer import BadDNS_zonetransfer
from .helpers import mock_signature_load

def from_xfr(*args, **kwargs):
    zone_text = """
@ 600 IN SOA ns.bad.dns. admin.bad.dns. (
    1   ; Serial
    3600   ; Refresh
    900   ; Retry
    604800   ; Expire
    86400 )  ; Minimum TTL
@ 600 IN NS ns.bad.dns.
@ 600 IN A 127.0.0.1
asdf 600 IN A 127.0.0.1
zzzz 600 IN AAAA dead::beef
"""
    zone = dns.zone.from_text(zone_text, origin="blacklanternsecurity.fakedomain.")
    return zone

@pytest.mark.asyncio
async def test_zonetransfer_discovery(fs, configure_mock_resolver, monkeypatch):

    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    mock_data = {"bad.dns": {"NS": ["ns1.bad.dns."]}, "ns1.bad.dns":{"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    baddns_zonetransfer = BadDNS_zonetransfer(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)
    
    monkeypatch.setattr("dns.zone.from_xfr", from_xfr)


    findings = None
    if await baddns_zonetransfer.dispatch():
        findings = baddns_zonetransfer.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Successful Zone Transfer",
        "confidence": "CONFIRMED",
        "signature": "N/A",
        "indicator": "Successful XFR Request",
        "trigger": "ns1.bad.dns",
        "module": "zonetransfer",
        "found_domains": ['bad.dns', 'asdf.bad.dns', 'zzzz.bad.dns']
    }
    assert any(expected == finding.to_dict() for finding in findings)