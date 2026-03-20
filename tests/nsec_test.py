import pytest
from baddns.modules.nsec import BadDNS_nsec


@pytest.mark.asyncio
async def test_nsec_match(mock_dispatch_whois, configure_mock_resolver):
    mock_data = {
        "bad.com": {"NSEC": ["asdf.bad.com"]},
        "asdf.bad.com": {"NSEC": ["zzzz.bad.com"]},
        "zzzz.bad.com": {"NSEC": ["xyz.bad.com"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"

    baddns_nsec = BadDNS_nsec(target, dns_client=mock_resolver)

    findings = None
    if await baddns_nsec.dispatch():
        findings = baddns_nsec.analyze()

    assert findings
    expected = {
        "target": "bad.com",
        "description": "DNSSEC NSEC Zone Walking Enabled for domain: [bad.com]",
        "confidence": "CONFIRMED",
        "severity": "INFO",
        "signature": "NSEC",
        "indicator": "NSEC Records",
        "trigger": "bad.com",
        "module": "NSEC",
        "found_domains": ["asdf.bad.com", "zzzz.bad.com", "xyz.bad.com"],
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_nsec_preventloop(mock_dispatch_whois, configure_mock_resolver):
    mock_data = {
        "wat.bad.com": {"NSEC": ["asdf.bad.com"]},
        "asdf.bad.com": {"NSEC": ["zzzz.bad.com"]},
        "zzzz.bad.com": {"NSEC": ["xyz.bad.com"]},
        "xyz.bad.com": {"NSEC": ["wat.bad.com"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)
    target = "wat.bad.com"

    baddns_nsec = BadDNS_nsec(target, dns_client=mock_resolver)

    findings = None
    if await baddns_nsec.dispatch():
        findings = baddns_nsec.analyze()

    assert findings

    for f in findings:
        print(f.to_dict())
    expected = {
        "target": "wat.bad.com",
        "description": "DNSSEC NSEC Zone Walking Enabled for domain: [wat.bad.com]",
        "confidence": "CONFIRMED",
        "severity": "INFO",
        "signature": "NSEC",
        "indicator": "NSEC Records",
        "trigger": "wat.bad.com",
        "module": "NSEC",
        "found_domains": ["asdf.bad.com", "zzzz.bad.com", "xyz.bad.com"],
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_nsec_preventwildcard(mock_dispatch_whois, configure_mock_resolver):
    mock_data = {
        "wat.bad.com": {"NSEC": ["wat.bad.com"]},
        "asdf.bad.com": {"NSEC": ["asdf.bad.com"]},
        "zzzz.bad.com": {"NSEC": ["zzzz.bad.com"]},
        "xyz.bad.com": {"NSEC": ["xyz.bad.com"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)

    for target in mock_data.keys():
        baddns_nsec = BadDNS_nsec(target, dns_client=mock_resolver)

        findings = None
        if await baddns_nsec.dispatch():
            findings = baddns_nsec.analyze()
        print(findings)
        assert not findings


@pytest.mark.asyncio
async def test_nsec_cname_false_positive(mock_dispatch_whois, configure_mock_resolver):
    """Target is a CNAME to a CDN. NSEC records belong to the CDN zone, not the target.
    This should be skipped to avoid false positives."""
    mock_data = {
        "sub.example.com": {"CNAME": ["cdn.provider.com"]},
        "cdn.provider.com": {"NSEC": ["cdn2.provider.com"]},
        "cdn2.provider.com": {"NSEC": ["cdn3.provider.com"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)
    target = "sub.example.com"

    baddns_nsec = BadDNS_nsec(target, dns_client=mock_resolver)

    findings = None
    if await baddns_nsec.dispatch():
        findings = baddns_nsec.analyze()

    assert not findings


@pytest.mark.asyncio
async def test_nsec_empty_chain(mock_dispatch_whois, configure_mock_resolver):
    """NSEC record exists but walk discovers no new domains. Should not be a finding."""
    mock_data = {
        "bad.com": {"NSEC": ["\\000.bad.com"]},
        "\\000.bad.com": {"NSEC": []},
    }
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"

    baddns_nsec = BadDNS_nsec(target, dns_client=mock_resolver)

    findings = None
    if await baddns_nsec.dispatch():
        findings = baddns_nsec.analyze()

    assert not findings


@pytest.mark.asyncio
async def test_nsec_walk_true_but_chain_empty(mock_dispatch_whois, configure_mock_resolver):
    """NSEC walk succeeds but all discovered domains start with backslash, so chain is empty after target removal."""
    mock_data = {
        "bad.com": {"NSEC": ["\\001.bad.com"]},
        "\\001.bad.com": {"NSEC": []},
    }
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"

    baddns_nsec = BadDNS_nsec(target, dns_client=mock_resolver)

    findings = None
    if await baddns_nsec.dispatch():
        findings = baddns_nsec.analyze()

    assert not findings


@pytest.mark.asyncio
async def test_nsec_all_nonmatching(mock_dispatch_whois, configure_mock_resolver):
    """All NSEC walk results are outside the target's base domain. Should not be a finding."""
    mock_data = {
        "bad.com": {"NSEC": ["foo.other.com"]},
        "foo.other.com": {"NSEC": ["bar.other.com"]},
        "bar.other.com": {"NSEC": ["baz.other.com"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"

    baddns_nsec = BadDNS_nsec(target, dns_client=mock_resolver)

    findings = None
    if await baddns_nsec.dispatch():
        findings = baddns_nsec.analyze()

    assert not findings
