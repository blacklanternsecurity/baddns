import pytest
from baddns.modules.dmarc import BadDNS_dmarc


@pytest.mark.asyncio
async def test_dmarc_no_txt_records(fs, configure_mock_resolver):
    mock_data = {}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 1
    f = findings[0].to_dict()
    assert f["indicator"] == "No DMARC record"
    assert f["confidence"] == "CONFIRMED"
    assert f["severity"] == "INFORMATIONAL"
    assert f["trigger"] == "_dmarc.bad.dns"
    assert f["module"] == "DMARC"


@pytest.mark.asyncio
async def test_dmarc_txt_exists_but_no_dmarc(fs, configure_mock_resolver):
    mock_data = {"_dmarc.bad.dns": {"TXT": ["v=spf1 include:example.com ~all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 1
    assert findings[0].to_dict()["indicator"] == "No DMARC record"


@pytest.mark.asyncio
async def test_dmarc_p_none(fs, configure_mock_resolver):
    mock_data = {"_dmarc.bad.dns": {"TXT": ["v=DMARC1; p=none; rua=mailto:dmarc@bad.dns"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "p=none" in indicators
    assert "No DMARC record" not in indicators


@pytest.mark.asyncio
async def test_dmarc_sp_none(fs, configure_mock_resolver):
    mock_data = {"_dmarc.bad.dns": {"TXT": ["v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@bad.dns"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "sp=none" in indicators
    assert "p=none" not in indicators


@pytest.mark.asyncio
async def test_dmarc_pct_less_than_100(fs, configure_mock_resolver):
    mock_data = {"_dmarc.bad.dns": {"TXT": ["v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@bad.dns"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "pct=50" in indicators


@pytest.mark.asyncio
async def test_dmarc_no_rua(fs, configure_mock_resolver):
    mock_data = {"_dmarc.bad.dns": {"TXT": ["v=DMARC1; p=reject"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "No rua tag" in indicators


@pytest.mark.asyncio
async def test_dmarc_fully_compliant(fs, configure_mock_resolver):
    mock_data = {"_dmarc.bad.dns": {"TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@bad.dns"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_dmarc_multiple_findings_p_none_no_rua(fs, configure_mock_resolver):
    mock_data = {"_dmarc.bad.dns": {"TXT": ["v=DMARC1; p=none"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "p=none" in indicators
    assert "No rua tag" in indicators
    assert len(findings) == 2


@pytest.mark.asyncio
async def test_dmarc_all_four_issues(fs, configure_mock_resolver):
    mock_data = {"_dmarc.bad.dns": {"TXT": ["v=DMARC1; p=none; sp=none; pct=25"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
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
async def test_dmarc_pct_100_no_finding(fs, configure_mock_resolver):
    mock_data = {"_dmarc.bad.dns": {"TXT": ["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@bad.dns"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    assert len(findings) == 0


@pytest.mark.asyncio
async def test_dmarc_p_quarantine_no_p_none_finding(fs, configure_mock_resolver):
    mock_data = {"_dmarc.bad.dns": {"TXT": ["v=DMARC1; p=quarantine; rua=mailto:dmarc@bad.dns"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "p=none" not in indicators


@pytest.mark.asyncio
async def test_dmarc_absent_sp_no_finding(fs, configure_mock_resolver):
    mock_data = {"_dmarc.bad.dns": {"TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@bad.dns"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "sp=none" not in indicators


@pytest.mark.asyncio
async def test_dmarc_case_insensitivity(fs, configure_mock_resolver):
    mock_data = {"_dmarc.bad.dns": {"TXT": ["V=DMARC1; P=None; RUA=mailto:dmarc@bad.dns"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert "p=none" in indicators


@pytest.mark.asyncio
async def test_dmarc_invalid_pct_no_crash(fs, configure_mock_resolver):
    mock_data = {"_dmarc.bad.dns": {"TXT": ["v=DMARC1; p=reject; pct=abc; rua=mailto:dmarc@bad.dns"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    m = BadDNS_dmarc(target, dns_client=mock_resolver)
    assert await m.dispatch()
    findings = m.analyze()
    indicators = [f.to_dict()["indicator"] for f in findings]
    assert not any(i.startswith("pct=") for i in indicators)
