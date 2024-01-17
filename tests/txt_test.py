import pytest
from baddns.modules.txt import BadDNS_txt
from .helpers import mock_signature_load


@pytest.mark.asyncio
async def test_txt_match(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {"TXT": ["baddns.azurewebsites.net"]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

    baddns_txt = BadDNS_txt(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)

    findings = None
    if await baddns_txt.dispatch():
        findings = baddns_txt.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Vulnerable Host in TXT Record. Original Event: [Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)]",
        "confidence": "PROBABLE",
        "signature": "Microsoft Azure Takeover Detection",
        "indicator": "azurewebsites.net",
        "trigger": "bad.dns",
        "module": "TXT",
    }
    for f in findings:
        print(f.to_dict())
    assert any(expected == finding.to_dict() for finding in findings)
