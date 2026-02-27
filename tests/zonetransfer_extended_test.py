import pytest
import dns
import dns.rcode
from unittest.mock import MagicMock
from baddns.modules.zonetransfer import BadDNS_zonetransfer


@pytest.mark.asyncio
async def test_zonetransfer_timeout(fs, configure_mock_resolver, monkeypatch):
    mock_data = {"bad.dns": {"NS": ["ns1.bad.dns."]}, "ns1.bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    baddns_zt = BadDNS_zonetransfer(target, dns_client=mock_resolver)
    monkeypatch.setattr("dns.zone.from_xfr", MagicMock(side_effect=TimeoutError))
    result = await baddns_zt.dispatch()
    assert result is False


@pytest.mark.asyncio
async def test_zonetransfer_connection_reset(fs, configure_mock_resolver, monkeypatch):
    mock_data = {"bad.dns": {"NS": ["ns1.bad.dns."]}, "ns1.bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    baddns_zt = BadDNS_zonetransfer("bad.dns", dns_client=mock_resolver)
    monkeypatch.setattr("dns.zone.from_xfr", MagicMock(side_effect=ConnectionResetError))
    result = await baddns_zt.dispatch()
    assert result is False


@pytest.mark.asyncio
async def test_zonetransfer_transfer_error(fs, configure_mock_resolver, monkeypatch):
    mock_data = {"bad.dns": {"NS": ["ns1.bad.dns."]}, "ns1.bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    baddns_zt = BadDNS_zonetransfer("bad.dns", dns_client=mock_resolver)
    monkeypatch.setattr("dns.zone.from_xfr", MagicMock(side_effect=dns.xfr.TransferError(rcode=dns.rcode.REFUSED)))
    result = await baddns_zt.dispatch()
    assert result is False


@pytest.mark.asyncio
async def test_zonetransfer_eof_error(fs, configure_mock_resolver, monkeypatch):
    mock_data = {"bad.dns": {"NS": ["ns1.bad.dns."]}, "ns1.bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    baddns_zt = BadDNS_zonetransfer("bad.dns", dns_client=mock_resolver)
    monkeypatch.setattr("dns.zone.from_xfr", MagicMock(side_effect=EOFError))
    result = await baddns_zt.dispatch()
    assert result is False


@pytest.mark.asyncio
async def test_zonetransfer_form_error(fs, configure_mock_resolver, monkeypatch):
    mock_data = {"bad.dns": {"NS": ["ns1.bad.dns."]}, "ns1.bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    baddns_zt = BadDNS_zonetransfer("bad.dns", dns_client=mock_resolver)
    monkeypatch.setattr("dns.zone.from_xfr", MagicMock(side_effect=dns.exception.FormError))
    result = await baddns_zt.dispatch()
    assert result is False


@pytest.mark.asyncio
async def test_zonetransfer_dns_timeout(fs, configure_mock_resolver, monkeypatch):
    mock_data = {"bad.dns": {"NS": ["ns1.bad.dns."]}, "ns1.bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    baddns_zt = BadDNS_zonetransfer("bad.dns", dns_client=mock_resolver)
    monkeypatch.setattr("dns.zone.from_xfr", MagicMock(side_effect=dns.exception.Timeout))
    result = await baddns_zt.dispatch()
    assert result is False


@pytest.mark.asyncio
async def test_zonetransfer_unknown_error(fs, configure_mock_resolver, monkeypatch):
    mock_data = {"bad.dns": {"NS": ["ns1.bad.dns."]}, "ns1.bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    baddns_zt = BadDNS_zonetransfer("bad.dns", dns_client=mock_resolver)
    monkeypatch.setattr("dns.zone.from_xfr", MagicMock(side_effect=RuntimeError("unknown")))
    result = await baddns_zt.dispatch()
    assert result is False


@pytest.mark.asyncio
async def test_zonetransfer_no_ns_records(fs, configure_mock_resolver):
    mock_data = {"bad.dns": {}}
    mock_resolver = configure_mock_resolver(mock_data)
    baddns_zt = BadDNS_zonetransfer("bad.dns", dns_client=mock_resolver)
    result = await baddns_zt.dispatch()
    assert result is False


@pytest.mark.asyncio
async def test_zonetransfer_no_ns_ip(fs, configure_mock_resolver, monkeypatch):
    mock_data = {"bad.dns": {"NS": ["ns1.bad.dns."]}}
    # ns1.bad.dns has no A record
    mock_resolver = configure_mock_resolver(mock_data)
    baddns_zt = BadDNS_zonetransfer("bad.dns", dns_client=mock_resolver)
    result = await baddns_zt.dispatch()
    assert result is False


@pytest.mark.asyncio
async def test_zonetransfer_empty_findings(fs, configure_mock_resolver, monkeypatch):
    mock_data = {"bad.dns": {"NS": ["ns1.bad.dns."]}, "ns1.bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    baddns_zt = BadDNS_zonetransfer("bad.dns", dns_client=mock_resolver)
    monkeypatch.setattr("dns.zone.from_xfr", MagicMock(side_effect=ConnectionResetError))
    await baddns_zt.dispatch()
    findings = baddns_zt.analyze()
    assert findings == []
