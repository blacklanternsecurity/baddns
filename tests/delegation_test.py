import pytest

from baddns.lib.loader import load_signatures
from baddns.modules.delegation import BadDNS_delegation
from .helpers import mock_signature_load


async def _run(fs, configure_mock_resolver, mock_data):
    mock_resolver = configure_mock_resolver(mock_data)
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    module = BadDNS_delegation("bad.dns", signatures=signatures, dns_client=mock_resolver)
    findings = []
    if await module.dispatch():
        findings = module.analyze()
    return [f.to_dict() for f in findings]


@pytest.mark.asyncio
async def test_delegation_acme_dangling(fs, mock_dispatch_whois, configure_mock_resolver):
    findings = await _run(
        fs,
        configure_mock_resolver,
        {
            "_acme-challenge.bad.dns": {"CNAME": ["baddns-acme.azurewebsites.net."]},
            "_NXDOMAIN": ["baddns-acme.azurewebsites.net"],
        },
    )
    assert findings
    acme = [f for f in findings if f["trigger"] == "_acme-challenge.bad.dns"]
    assert acme
    assert acme[0]["target"] == "bad.dns"
    assert acme[0]["severity"] == "HIGH"
    assert acme[0]["description"].startswith("Dangling ACME delegation [_acme-challenge.bad.dns]")
    assert acme[0]["module"] == "DELEGATION"


@pytest.mark.asyncio
async def test_delegation_dkim_dangling(fs, mock_dispatch_whois, configure_mock_resolver):
    findings = await _run(
        fs,
        configure_mock_resolver,
        {
            "selector1._domainkey.bad.dns": {"CNAME": ["baddns-dkim.azurewebsites.net."]},
            "_NXDOMAIN": ["baddns-dkim.azurewebsites.net"],
        },
    )
    dkim = [f for f in findings if f["trigger"] == "selector1._domainkey.bad.dns"]
    assert dkim and dkim[0]["description"].startswith("Dangling DKIM delegation")


@pytest.mark.asyncio
async def test_delegation_no_cnames(fs, mock_dispatch_whois, configure_mock_resolver):
    findings = await _run(fs, configure_mock_resolver, {"bad.dns": {"A": ["127.0.0.1"]}})
    assert findings == []


@pytest.mark.asyncio
async def test_delegation_healthy_cname(fs, mock_dispatch_whois, configure_mock_resolver):
    findings = await _run(
        fs,
        configure_mock_resolver,
        {
            "_dmarc.bad.dns": {"CNAME": ["dmarc.vendor.example."]},
            "dmarc.vendor.example": {"TXT": ["v=DMARC1; p=reject"]},
        },
    )
    assert findings == []


def test_delegation_label_shapes():
    from baddns.base import BadDNS_base

    ok = ["_acme-challenge.bad.dns", "_dmarc.bad.dns", "selector1._domainkey.bad.dns"]
    not_ok = [
        "bill._tcp.app.flipster.io",
        "_sip._tls.bad.dns",
        "_acme-challenge._tcp.bad.dns",
        "_x._domainkey.bad.dns",
    ]
    assert all(BadDNS_base.is_delegation_label(t) for t in ok)
    assert not any(BadDNS_base.is_delegation_label(t) for t in not_ok)


@pytest.mark.asyncio
async def test_srv_style_still_skipped_without_flag(fs, mock_dispatch_whois, configure_mock_resolver):
    """The exception only applies when the DELEGATION module asks for it."""
    from baddns.modules.cname import BadDNS_cname

    mock_resolver = configure_mock_resolver(
        {"_acme-challenge.bad.dns": {"CNAME": ["x.azurewebsites.net."]}, "_NXDOMAIN": ["x.azurewebsites.net"]}
    )
    assert await BadDNS_cname("_acme-challenge.bad.dns", dns_client=mock_resolver).dispatch() is False


@pytest.mark.asyncio
async def test_delegation_rotating_dkim_selector_not_reported(fs, mock_dispatch_whois, configure_mock_resolver):
    """Microsoft 365 publishes one DKIM selector of a pair; the other CNAME targets a name that doesn't exist yet."""
    findings = await _run(
        fs,
        configure_mock_resolver,
        {
            "selector2._domainkey.bad.dns": {"CNAME": ["selector2-bad-dns._domainkey.bad.onmicrosoft.com."]},
            "_NXDOMAIN": ["selector2-bad-dns._domainkey.bad.onmicrosoft.com"],
        },
    )
    assert findings == []
