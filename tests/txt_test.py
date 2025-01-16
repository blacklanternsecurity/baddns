import pytest
from baddns.modules.txt import BadDNS_txt
from baddns.lib.loader import load_signatures
from .helpers import mock_signature_load


@pytest.mark.asyncio
async def test_txt_match(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {"TXT": ["baddns.azurewebsites.net"]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_txt = BadDNS_txt(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_txt.dispatch():
        findings = baddns_txt.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Vulnerable Host [baddns.azurewebsites.net] in TXT Record. Original Event: [Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)]",
        "confidence": "PROBABLE",
        "signature": "Microsoft Azure Takeover Detection",
        "indicator": "azurewebsites.net",
        "trigger": "bad.dns",
        "module": "TXT",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_txt_dontmatchip(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {
        "bad.dns": {"TXT": ["some text 100.100.100.100 some more text"]},
        "_NXDOMAIN": ["baddns.azurewebsites.net"],
    }
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_txt = BadDNS_txt(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_txt.dispatch():
        findings = baddns_txt.analyze()

    assert not findings
