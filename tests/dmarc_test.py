import pytest
from baddns.modules.dmarc import BadDNS_dmarc


class TestParseDmarcRecord:
    def test_empty_part_skipped(self):
        """Empty parts from trailing/double semicolons should be skipped (line 32)."""
        result = BadDNS_dmarc.parse_dmarc_record("v=DMARC1; ; p=reject")
        assert result is not None
        assert result["p"] == "reject"

    def test_no_separator_skipped(self):
        """Parts without '=' should be skipped (line 35)."""
        result = BadDNS_dmarc.parse_dmarc_record("v=DMARC1; badpart; p=reject")
        assert result is not None
        assert "badpart" not in result
        assert result["p"] == "reject"


@pytest.mark.asyncio
async def test_dmarc_no_txt_records(configure_mock_resolver):
    mock_data = {}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 1
    f = findings[0].to_dict()
    assert f["indicator"] == "No DMARC record"
    assert f["confidence"] == "CONFIRMED"
    assert f["severity"] == "INFORMATIONAL"
    assert f["trigger"] == "_dmarc.bad.com"
    assert f["module"] == "DMARC"


@pytest.mark.asyncio
async def test_dmarc_txt_exists_but_no_dmarc(configure_mock_resolver):
    mock_data = {"_dmarc.bad.com": {"TXT": ["v=spf1 include:example.com ~all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 1
    assert findings[0].to_dict()["indicator"] == "No DMARC record"


@pytest.mark.asyncio
async def test_dmarc_p_none(configure_mock_resolver):
    mock_data = {"_dmarc.bad.com": {"TXT": ["v=DMARC1; p=none; rua=mailto:dmarc@bad.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "p=none" in indicators
    assert "No DMARC record" not in indicators


@pytest.mark.asyncio
async def test_dmarc_sp_none(configure_mock_resolver):
    mock_data = {"_dmarc.bad.com": {"TXT": ["v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@bad.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "sp=none" in indicators
    assert "p=none" not in indicators


@pytest.mark.asyncio
async def test_dmarc_pct_less_than_100(configure_mock_resolver):
    mock_data = {"_dmarc.bad.com": {"TXT": ["v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@bad.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "pct=50" in indicators


@pytest.mark.asyncio
async def test_dmarc_no_rua(configure_mock_resolver):
    mock_data = {"_dmarc.bad.com": {"TXT": ["v=DMARC1; p=reject"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "No rua tag" in indicators


@pytest.mark.asyncio
async def test_dmarc_fully_compliant(configure_mock_resolver):
    mock_data = {"_dmarc.bad.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@bad.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_dmarc_multiple_findings_p_none_no_rua(configure_mock_resolver):
    mock_data = {"_dmarc.bad.com": {"TXT": ["v=DMARC1; p=none"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "p=none" in indicators
    assert "No rua tag" in indicators
    assert len(findings) == 2


@pytest.mark.asyncio
async def test_dmarc_all_four_issues(configure_mock_resolver):
    mock_data = {"_dmarc.bad.com": {"TXT": ["v=DMARC1; p=none; sp=none; pct=25"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "p=none" in indicators
    assert "sp=none" in indicators
    assert "pct=25" in indicators
    assert "No rua tag" in indicators
    assert len(findings) == 4


@pytest.mark.asyncio
async def test_dmarc_pct_100_no_finding(configure_mock_resolver):
    mock_data = {"_dmarc.bad.com": {"TXT": ["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@bad.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_dmarc_p_quarantine_no_p_none_finding(configure_mock_resolver):
    mock_data = {"_dmarc.bad.com": {"TXT": ["v=DMARC1; p=quarantine; rua=mailto:dmarc@bad.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "p=none" not in indicators


@pytest.mark.asyncio
async def test_dmarc_absent_sp_no_finding(configure_mock_resolver):
    mock_data = {"_dmarc.bad.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@bad.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "sp=none" not in indicators


@pytest.mark.asyncio
async def test_dmarc_case_insensitivity(configure_mock_resolver):
    mock_data = {"_dmarc.bad.com": {"TXT": ["V=DMARC1; P=None; RUA=mailto:dmarc@bad.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "p=none" in indicators


@pytest.mark.asyncio
async def test_dmarc_invalid_pct_no_crash(configure_mock_resolver):
    mock_data = {"_dmarc.bad.com": {"TXT": ["v=DMARC1; p=reject; pct=abc; rua=mailto:dmarc@bad.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert not any(i.startswith("pct=") for i in indicators)


# --- Subdomain inheritance tests (RFC 7489 Section 6.6.3) ---


@pytest.mark.asyncio
async def test_dmarc_subdomain_inherits_reject(configure_mock_resolver):
    """Subdomain has no DMARC, but org domain has p=reject. Subdomain is protected."""
    mock_data = {"_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "sub.example.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_dmarc_subdomain_inherits_sp_none(configure_mock_resolver):
    """Org domain has p=reject but sp=none. Subdomain is NOT protected."""
    mock_data = {"_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "sub.example.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 1
    f = findings[0].to_dict()
    assert "Inherited policy: none" in f["indicator"]


@pytest.mark.asyncio
async def test_dmarc_subdomain_inherits_p_none(configure_mock_resolver):
    """Org domain has p=none (no sp). Subdomain inherits p=none — not protected."""
    mock_data = {"_dmarc.example.com": {"TXT": ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "sub.example.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "Inherited policy: none" in indicators


@pytest.mark.asyncio
async def test_dmarc_subdomain_no_org_record(configure_mock_resolver):
    """Subdomain has no DMARC and org domain has no DMARC either. Report missing."""
    mock_data = {}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "sub.example.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 1
    assert findings[0].to_dict()["indicator"] == "No DMARC record"


@pytest.mark.asyncio
async def test_dmarc_subdomain_own_record_overrides(configure_mock_resolver):
    """Subdomain has its own DMARC record — should use it, not fall back to org."""
    mock_data = {
        "_dmarc.sub.example.com": {"TXT": ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]},
        "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)
    target = "sub.example.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "p=none" in indicators
    assert "No DMARC record" not in indicators


@pytest.mark.asyncio
async def test_dmarc_subdomain_inherits_sp_quarantine(configure_mock_resolver):
    """Org domain has sp=quarantine. Subdomain is protected."""
    mock_data = {"_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "sub.example.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_dmarc_subdomain_inherits_low_pct(configure_mock_resolver):
    """Org domain has p=reject but pct=25. Subdomain inherits the partial application."""
    mock_data = {"_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; pct=25; rua=mailto:dmarc@example.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "sub.example.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "pct=25" in indicators
    assert "No DMARC record" not in indicators


@pytest.mark.asyncio
async def test_dmarc_deep_subdomain_inherits(configure_mock_resolver):
    """Deep subdomain (a.b.example.com) falls back to _dmarc.example.com per RFC 7489."""
    mock_data = {"_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "a.b.example.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_dmarc_subdomain_inherited_invalid_pct(configure_mock_resolver):
    """Org DMARC record with non-numeric pct should not crash (inherited ValueError path)."""
    mock_data = {"_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; pct=abc; rua=mailto:dmarc@example.com"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "sub.example.com"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert not any(i.startswith("pct=") for i in indicators)
