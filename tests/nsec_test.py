import pytest
from baddns.modules.nsec import BadDNS_nsec


@pytest.mark.asyncio
async def test_nsec_match(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {
        "bad.dns": {"NSEC": ["asdf.bad.dns"]},
        "asdf.bad.dns": {"NSEC": ["zzzz.bad.dns"]},
        "zzzz.bad.dns": {"NSEC": ["xyz.bad.dns"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"

    baddns_nsec = BadDNS_nsec(target, dns_client=mock_resolver)

    findings = None
    if await baddns_nsec.dispatch():
        findings = baddns_nsec.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "DNSSEC NSEC Zone Walking Enabled for domain: [bad.dns]",
        "confidence": "CONFIRMED",
        "signature": "N/A",
        "indicator": "NSEC Records",
        "trigger": "bad.dns",
        "module": "NSEC",
        "found_domains": ["asdf.bad.dns", "zzzz.bad.dns", "xyz.bad.dns"],
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_nsec_preventloop(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {
        "wat.bad.dns": {"NSEC": ["asdf.bad.dns"]},
        "asdf.bad.dns": {"NSEC": ["zzzz.bad.dns"]},
        "zzzz.bad.dns": {"NSEC": ["xyz.bad.dns"]},
        "xyz.bad.dns": {"NSEC": ["wat.bad.dns"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)
    target = "wat.bad.dns"

    baddns_nsec = BadDNS_nsec(target, dns_client=mock_resolver)

    findings = None
    if await baddns_nsec.dispatch():
        findings = baddns_nsec.analyze()

    assert findings

    for f in findings:
        print(f.to_dict())
    expected = {
        "target": "wat.bad.dns",
        "description": "DNSSEC NSEC Zone Walking Enabled for domain: [wat.bad.dns]",
        "confidence": "CONFIRMED",
        "signature": "N/A",
        "indicator": "NSEC Records",
        "trigger": "wat.bad.dns",
        "module": "NSEC",
        "found_domains": ["asdf.bad.dns", "zzzz.bad.dns", "xyz.bad.dns"],
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_nsec_preventwildcard(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {
        "wat.bad.dns": {"NSEC": ["wat.bad.dns"]},
        "asdf.bad.dns": {"NSEC": ["asdf.bad.dns"]},
        "zzzz.bad.dns": {"NSEC": ["zzzz.bad.dns"]},
        "xyz.bad.dns": {"NSEC": ["xyz.bad.dns"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)

    for target in mock_data.keys():
        baddns_nsec = BadDNS_nsec(target, dns_client=mock_resolver)

        findings = None
        if await baddns_nsec.dispatch():
            findings = baddns_nsec.analyze()
        print(findings)
        assert not findings
