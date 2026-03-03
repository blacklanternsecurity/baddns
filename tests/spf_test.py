import pytest
import datetime
from unittest.mock import patch
from baddns.modules.spf import BadDNS_spf

mock_whois_unregistered = {
    "type": "error",
    "data": 'No match for "WORSE.DNS".\r\n>>> Last update of whois database: 2023-08-17T14:07:31Z <<<\r\n',
}

mock_whois_expired = {
    "type": "response",
    "data": {
        "domain_name": ["WORSE.DNS", "worse.dns"],
        "registrar": "Google LLC",
        "whois_server": "whois.google.com",
        "referral_url": None,
        "updated_date": datetime.datetime(2022, 4, 26, 17, 5, 40),
        "creation_date": datetime.datetime(2020, 4, 25, 15, 56, 10),
        "expiration_date": datetime.datetime(2023, 2, 25, 15, 56, 10),
        "name_servers": ["NS-CLOUD-B1.GOOGLEDOMAINS.COM"],
        "status": ["clientTransferProhibited https://icann.org/epp#clientTransferProhibited"],
        "emails": "registrar-abuse@google.com",
        "dnssec": "unsigned",
        "name": "Contact Privacy Inc.",
        "org": "Contact Privacy Inc.",
        "address": "96 Mowat Ave",
        "city": "Toronto",
        "state": "ON",
        "registrant_postal_code": "M4K 3K1",
        "country": "CA",
    },
}

mock_whois_registered = {
    "type": "response",
    "data": {
        "domain_name": ["WORSE.DNS", "worse.dns"],
        "registrar": "Google LLC",
        "whois_server": "whois.google.com",
        "referral_url": None,
        "updated_date": datetime.datetime(2022, 4, 26, 17, 5, 40),
        "creation_date": datetime.datetime(2020, 4, 25, 15, 56, 10),
        "expiration_date": datetime.datetime(2099, 2, 25, 15, 56, 10),
        "name_servers": ["NS-CLOUD-B1.GOOGLEDOMAINS.COM"],
        "status": ["clientTransferProhibited https://icann.org/epp#clientTransferProhibited"],
        "emails": "registrar-abuse@google.com",
        "dnssec": "unsigned",
        "name": "Contact Privacy Inc.",
        "org": "Contact Privacy Inc.",
        "address": "96 Mowat Ave",
        "city": "Toronto",
        "state": "ON",
        "registrant_postal_code": "M4K 3K1",
        "country": "CA",
    },
}


# --- Policy tests (DNS mock only) ---


@pytest.mark.asyncio
async def test_spf_no_txt_records(configure_mock_resolver):
    mock_data = {}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 1
    f = findings[0].to_dict()
    assert f["indicator"] == "No SPF record"
    assert f["confidence"] == "CONFIRMED"
    assert f["severity"] == "INFORMATIONAL"
    assert f["trigger"] == "bad.com"
    assert f["module"] == "SPF"


@pytest.mark.asyncio
async def test_spf_txt_exists_but_no_spf(configure_mock_resolver):
    mock_data = {"bad.com": {"TXT": ["v=DMARC1; p=reject"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 1
    assert findings[0].to_dict()["indicator"] == "No SPF record"


@pytest.mark.asyncio
async def test_spf_plus_all(configure_mock_resolver):
    mock_data = {"bad.com": {"TXT": ["v=spf1 +all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "+all" in indicators


@pytest.mark.asyncio
async def test_spf_bare_all_implicit_plus(configure_mock_resolver):
    """Bare 'all' without qualifier defaults to +all."""
    mock_data = {"bad.com": {"TXT": ["v=spf1 all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "+all" in indicators


@pytest.mark.asyncio
async def test_spf_neutral_all(configure_mock_resolver):
    mock_data = {"bad.com": {"TXT": ["v=spf1 ?all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "?all" in indicators
    assert "+all" not in indicators


@pytest.mark.asyncio
async def test_spf_softfail_all_no_finding(configure_mock_resolver):
    """~all should not produce a finding."""
    mock_data = {"bad.com": {"TXT": ["v=spf1 ~all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "+all" not in indicators
    assert "?all" not in indicators


@pytest.mark.asyncio
async def test_spf_hardfail_all_no_finding(configure_mock_resolver):
    """-all should not produce a finding."""
    mock_data = {"bad.com": {"TXT": ["v=spf1 -all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_spf_multiple_records(configure_mock_resolver):
    mock_data = {"bad.com": {"TXT": ["v=spf1 -all", "v=spf1 include:example.com -all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "Multiple SPF records (2)" in indicators


@pytest.mark.asyncio
async def test_spf_dns_lookup_exceeds_10(configure_mock_resolver):
    """11 DNS lookup mechanisms should trigger a finding."""
    includes = " ".join([f"include:spf{i}.example.com" for i in range(11)])
    mock_data = {"bad.com": {"TXT": [f"v=spf1 {includes} -all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "DNS lookup count: 11" in indicators


@pytest.mark.asyncio
async def test_spf_dns_lookup_at_10_no_finding(configure_mock_resolver):
    """Exactly 10 DNS lookup mechanisms should not trigger a finding."""
    includes = " ".join([f"include:spf{i}.example.com" for i in range(10)])
    mock_data = {"bad.com": {"TXT": [f"v=spf1 {includes} -all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert not any(i.startswith("DNS lookup count:") for i in indicators)


@pytest.mark.asyncio
async def test_spf_mixed_mechanisms_counting(configure_mock_resolver):
    """ip4/ip6 don't count toward DNS lookups; a/mx/include/ptr/exists/redirect do."""
    mock_data = {
        "bad.com": {
            "TXT": [
                "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 include:a.com include:b.com "
                "a mx ptr exists:%{i}.spf.example.com redirect=c.com"
            ]
        }
    }
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    # 2 includes + a + mx + ptr + exists + redirect = 7
    assert m.parsed_spf["dns_lookup_count"] == 7


@pytest.mark.asyncio
async def test_spf_fully_compliant(configure_mock_resolver):
    """A well-formed SPF record should produce no findings."""
    mock_data = {"bad.com": {"TXT": ["v=spf1 include:_spf.google.com ~all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_spf_case_insensitive(configure_mock_resolver):
    """V=SPF1 (uppercase) should be recognized as a valid SPF record."""
    mock_data = {"bad.com": {"TXT": ["V=SPF1 -all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_spf_no_all_mechanism_no_finding(configure_mock_resolver):
    """Missing 'all' mechanism should not trigger +all or ?all findings."""
    mock_data = {"bad.com": {"TXT": ["v=spf1 include:example.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "+all" not in indicators
    assert "?all" not in indicators


@pytest.mark.asyncio
async def test_spf_qualified_mechanisms_parsed(configure_mock_resolver):
    """Mechanisms with explicit qualifier prefixes like ~include: should be parsed correctly."""
    mock_data = {"bad.com": {"TXT": ["v=spf1 ~include:example.com -mx -all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    assert m.parsed_spf["includes"] == ["example.com"]
    assert m.parsed_spf["dns_lookup_count"] == 2  # include + mx


@pytest.mark.asyncio
async def test_spf_empty_include_no_crash(configure_mock_resolver):
    """An include: with no domain should not crash WHOIS lookups."""
    mock_data = {"bad.com": {"TXT": ["v=spf1 include: -all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert not any(f.to_dict()["indicator"] == "Whois Data" for f in findings)


# --- Takeover tests (WHOIS mock, MX test pattern) ---


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_unregistered], indirect=True)
async def test_spf_include_unregistered(fs, mock_dispatch_whois, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"TXT": ["v=spf1 include:worse.dns -all"]}}
        mock_resolver = configure_mock_resolver(mock_data)

        target = "bad.dns"
        m = BadDNS_spf(target, dns_client=mock_resolver)
        findings = None
        if await m.dispatch():
            findings = m.analyze()
        assert not exit_mock.called

        expected = {
            "target": "bad.dns",
            "description": "SPF include unregistered",
            "confidence": "CONFIRMED",
            "severity": "MEDIUM",
            "signature": "N/A",
            "indicator": "Whois Data",
            "trigger": "worse.dns",
            "module": "SPF",
        }
        assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_expired], indirect=True)
async def test_spf_include_expired(fs, mock_dispatch_whois, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"TXT": ["v=spf1 include:worse.dns -all"]}}
        mock_resolver = configure_mock_resolver(mock_data)

        target = "bad.dns"
        m = BadDNS_spf(target, dns_client=mock_resolver)
        findings = None
        if await m.dispatch():
            findings = m.analyze()
        assert not exit_mock.called

        expected = {
            "target": "bad.dns",
            "description": "SPF include Registration Expired (Expiration: [2023-02-25 15:56:10]",
            "confidence": "CONFIRMED",
            "severity": "MEDIUM",
            "signature": "N/A",
            "indicator": "Whois Data",
            "trigger": "worse.dns",
            "module": "SPF",
        }
        assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_unregistered], indirect=True)
async def test_spf_redirect_unregistered(fs, mock_dispatch_whois, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"TXT": ["v=spf1 redirect=worse.dns"]}}
        mock_resolver = configure_mock_resolver(mock_data)

        target = "bad.dns"
        m = BadDNS_spf(target, dns_client=mock_resolver)
        findings = None
        if await m.dispatch():
            findings = m.analyze()
        assert not exit_mock.called

        expected = {
            "target": "bad.dns",
            "description": "SPF redirect unregistered",
            "confidence": "CONFIRMED",
            "severity": "MEDIUM",
            "signature": "N/A",
            "indicator": "Whois Data",
            "trigger": "worse.dns",
            "module": "SPF",
        }
        assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_registered], indirect=True)
async def test_spf_include_registered_no_finding(fs, mock_dispatch_whois, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"TXT": ["v=spf1 include:worse.dns -all"]}}
        mock_resolver = configure_mock_resolver(mock_data)

        target = "bad.dns"
        m = BadDNS_spf(target, dns_client=mock_resolver)
        findings = None
        if await m.dispatch():
            findings = m.analyze()
        assert not exit_mock.called
        assert not any(f.to_dict()["indicator"] == "Whois Data" for f in findings)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_unregistered], indirect=True)
async def test_spf_combined_policy_and_takeover(fs, mock_dispatch_whois, configure_mock_resolver, cached_suffix_list):
    """Both +all policy issue and include takeover should be reported."""
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"TXT": ["v=spf1 include:worse.dns +all"]}}
        mock_resolver = configure_mock_resolver(mock_data)

        target = "bad.dns"
        m = BadDNS_spf(target, dns_client=mock_resolver)
        findings = None
        if await m.dispatch():
            findings = m.analyze()
        assert not exit_mock.called

        indicators = [f.to_dict()["indicator"] for f in findings]
        assert "+all" in indicators
        assert "Whois Data" in indicators


# --- Subdomain inheritance tests ---


@pytest.mark.asyncio
async def test_spf_subdomain_inherits_from_org(configure_mock_resolver):
    """Subdomain has no SPF, but org domain does. Subdomain is covered — no 'No SPF record' finding."""
    mock_data = {"example.com": {"TXT": ["v=spf1 include:_spf.google.com -all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "www.example.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "No SPF record" not in indicators
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_spf_subdomain_inherits_policy_issues(configure_mock_resolver):
    """Subdomain has no SPF, org domain has +all. Policy issue should propagate."""
    mock_data = {"example.com": {"TXT": ["v=spf1 +all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "www.example.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "+all" in indicators
    assert "No SPF record" not in indicators


@pytest.mark.asyncio
async def test_spf_subdomain_no_org_record(configure_mock_resolver):
    """Subdomain has no SPF and org domain has no SPF either. Report missing."""
    mock_data = {}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "www.example.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 1
    assert findings[0].to_dict()["indicator"] == "No SPF record"


@pytest.mark.asyncio
async def test_spf_subdomain_own_record_overrides(configure_mock_resolver):
    """Subdomain has its own SPF record — should use it, not fall back to org."""
    mock_data = {
        "sub.example.com": {"TXT": ["v=spf1 +all"]},
        "example.com": {"TXT": ["v=spf1 -all"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)
    target = "sub.example.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "+all" in indicators


@pytest.mark.asyncio
async def test_spf_deep_subdomain_inherits(configure_mock_resolver):
    """Deep subdomain (a.b.example.com) falls back to example.com."""
    mock_data = {"example.com": {"TXT": ["v=spf1 include:_spf.google.com -all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "a.b.example.com"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_unregistered], indirect=True)
async def test_spf_subdomain_inherits_takeover(fs, mock_dispatch_whois, configure_mock_resolver, cached_suffix_list):
    """Subdomain has no SPF, org domain SPF has hijackable include — should report takeover."""
    with patch("sys.exit") as exit_mock:
        mock_data = {"example.com": {"TXT": ["v=spf1 include:worse.dns -all"]}}
        mock_resolver = configure_mock_resolver(mock_data)

        target = "www.example.com"
        m = BadDNS_spf(target, dns_client=mock_resolver)
        findings = None
        if await m.dispatch():
            findings = m.analyze()
        assert not exit_mock.called

        expected = {
            "target": "www.example.com",
            "description": "SPF include unregistered",
            "confidence": "CONFIRMED",
            "severity": "MEDIUM",
            "signature": "N/A",
            "indicator": "Whois Data",
            "trigger": "worse.dns",
            "module": "SPF",
        }
        assert any(expected == finding.to_dict() for finding in findings)


# --- Cloud provider skip tests ---


@pytest.mark.asyncio
async def test_spf_cloud_target_skipped(configure_mock_resolver):
    """Cloud provider targets should be skipped for SPF checks."""
    mock_data = {}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "vinrclsql1-eus2.azurewebsites.net"
    m = BadDNS_spf(target, dns_client=mock_resolver)
    with patch("baddns.base.cloudcheck", return_value=[("Azure", "cloud", "azurewebsites.net")]):
        result = await m.dispatch()
    assert result is False
