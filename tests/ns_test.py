import pytest

from baddns.modules.ns import BadDNS_ns
from baddns.lib.loader import load_signatures
from .helpers import mock_signature_load


@pytest.mark.asyncio
async def test_ns_nosoa_signature(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {"NS": ["ns1.wordpress.com."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=["ns1.wordpress.com"])

    target = "bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns(target, signatures=signatures, dns_client=mock_resolver)
    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling NS Records (NS records without SOA) with known impact",
        "confidence": "MEDIUM",
        "severity": "MEDIUM",
        "signature": "wordpress.com",
        "indicator": "DnsWalk Analysis with signature match: ['ns1.wordpress.com']",
        "trigger": "ns1.wordpress.com",
        "module": "NS",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_ns_nosoa_generic(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {"NS": ["ns1.somerandomthing.com."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=["ns1.somerandomthing.com"])

    target = "bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling NS Records (NS records without SOA)",
        "confidence": "LOW",
        "severity": "MEDIUM",
        "signature": "GENERIC",
        "indicator": "DNSWalk Analysis",
        "trigger": "ns1.somerandomthing.com",
        "module": "NS",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_ns_nosoa_negative_signature(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {"NS": ["pdns1.ultradns.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=["pdns1.ultradns.net"])

    target = "bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")
    mock_signature_load(fs, "negative_ultradns_ns.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert not findings


@pytest.mark.asyncio
async def test_ns_nosoa_positive_with_negative_loaded(fs, mock_dispatch_whois, configure_mock_resolver):
    """Positive signature still fires when negative signatures are also loaded."""
    mock_data = {"bad.dns": {"NS": ["ns1.wordpress.com."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=["ns1.wordpress.com"])

    target = "bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")
    mock_signature_load(fs, "negative_ultradns_ns.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling NS Records (NS records without SOA) with known impact",
        "confidence": "MEDIUM",
        "severity": "MEDIUM",
        "signature": "wordpress.com",
        "indicator": "DnsWalk Analysis with signature match: ['ns1.wordpress.com']",
        "trigger": "ns1.wordpress.com",
        "module": "NS",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_ns_nosoa_generic_with_negative_loaded(fs, mock_dispatch_whois, configure_mock_resolver):
    """Generic finding still fires when negative signatures are loaded but don't match."""
    mock_data = {"bad.dns": {"NS": ["ns1.somerandomthing.com."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=["ns1.somerandomthing.com"])

    target = "bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")
    mock_signature_load(fs, "negative_ultradns_ns.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling NS Records (NS records without SOA)",
        "confidence": "LOW",
        "severity": "MEDIUM",
        "signature": "GENERIC",
        "indicator": "DNSWalk Analysis",
        "trigger": "ns1.somerandomthing.com",
        "module": "NS",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_ns_nosoa_negative_signature_disabled(fs, mock_dispatch_whois, configure_mock_resolver):
    """With disable_negative_signatures, generic finding fires even when negative signature matches."""
    mock_data = {"bad.dns": {"NS": ["pdns1.ultradns.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=["pdns1.ultradns.net"])

    target = "bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")
    mock_signature_load(fs, "negative_ultradns_ns.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns(target, signatures=signatures, dns_client=mock_resolver, disable_negative_signatures=True)

    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling NS Records (NS records without SOA)",
        "confidence": "LOW",
        "severity": "MEDIUM",
        "signature": "GENERIC",
        "indicator": "DNSWalk Analysis",
        "trigger": "pdns1.ultradns.net",
        "module": "NS",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_ns_label_too_long(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {}
    mock_resolver = configure_mock_resolver(mock_data)

    target = "a" * 64 + ".bad.dns"
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert not findings


# --- nameserver domain WHOIS ---

mock_whois_ns_unregistered = {"type": "error", "data": 'No match for "DEADNSPROVIDER.COM".'}


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_ns_unregistered], indirect=True)
async def test_ns_nameserver_domain_unregistered(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {"NS": ["ns1.deadnsprovider.com.", "ns2.deadnsprovider.com."]}}
    mock_resolver = configure_mock_resolver(
        mock_data, mock_dnswalk_data=["ns1.deadnsprovider.com", "ns2.deadnsprovider.com"]
    )
    mock_signature_load(fs, "dnsreaper_wordpress_com_ns.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns("bad.dns", signatures=signatures, dns_client=mock_resolver)
    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()

    assert findings
    whois_findings = [f.to_dict() for f in findings if f.to_dict()["indicator"] == "Whois Data"]
    assert len(whois_findings) == 1  # both nameservers share one registered domain
    assert whois_findings[0]["confidence"] == "CONFIRMED"
    assert whois_findings[0]["severity"] == "HIGH"
    assert "unregistered" in whois_findings[0]["description"]
    assert whois_findings[0]["trigger"] == "ns1.deadnsprovider.com, ns2.deadnsprovider.com"


# --- partially dangling delegations ---


def _response(rcode, authoritative):
    import dns.flags
    import dns.message
    import dns.rdatatype

    msg = dns.message.make_response(dns.message.make_query("bad.dns", dns.rdatatype.SOA))
    msg.set_rcode(rcode)
    if authoritative:
        msg.flags |= dns.flags.AA
    else:
        msg.flags &= ~dns.flags.AA
    return msg


async def _run_partial(fs, configure_mock_resolver, monkeypatch, responses, nameservers=None):
    from baddns.lib.dnswalk import DnsWalk

    nameservers = nameservers or ["ns1.digitalocean.com", "ns1.live-provider.net"]
    mock_data = {"bad.dns": {"SOA": ["ns1.live-provider.net. admin.bad.dns. 1 3600 900 604800 86400"]}}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=nameservers)
    queried = []

    async def fake_a_resolve(self, nameserver, glue=None):
        return ["192.0.2.1"]

    responses = iter(responses)

    async def fake_raw_query(self, query, nameserver_ip):
        queried.append(nameserver_ip)
        return next(responses), False

    monkeypatch.setattr(DnsWalk, "a_resolve", fake_a_resolve)
    monkeypatch.setattr(DnsWalk, "raw_query_with_retry", fake_raw_query)
    mock_signature_load(fs, "dnsreaper_digitalocean.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns("bad.dns", signatures=signatures, dns_client=mock_resolver)
    findings = []
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze() or []
    return [f.to_dict() for f in findings], queried


@pytest.mark.asyncio
async def test_ns_partial_lame_confirmed(fs, mock_dispatch_whois, configure_mock_resolver, monkeypatch):
    import dns.rcode

    findings, queried = await _run_partial(
        fs, configure_mock_resolver, monkeypatch, [_response(dns.rcode.REFUSED, False)] * 2
    )
    partial = [f for f in findings if f["description"].startswith("Partially dangling")]
    assert len(partial) == 1
    assert partial[0]["trigger"] == "ns1.digitalocean.com"
    assert partial[0]["signature"] == "digitalocean.com"
    assert partial[0]["confidence"] == "MEDIUM"
    assert len(queried) == 2  # only the claimable-provider nameserver is queried, twice


@pytest.mark.asyncio
async def test_ns_partial_lame_timeout_not_reported(fs, mock_dispatch_whois, configure_mock_resolver, monkeypatch):
    findings, _ = await _run_partial(fs, configure_mock_resolver, monkeypatch, [None, None])
    assert not [f for f in findings if f["description"].startswith("Partially dangling")]


@pytest.mark.asyncio
async def test_ns_partial_lame_requires_both_answers(fs, mock_dispatch_whois, configure_mock_resolver, monkeypatch):
    import dns.rcode

    findings, _ = await _run_partial(
        fs,
        configure_mock_resolver,
        monkeypatch,
        [_response(dns.rcode.REFUSED, False), _response(dns.rcode.NOERROR, True)],
    )
    assert not [f for f in findings if f["description"].startswith("Partially dangling")]


@pytest.mark.asyncio
async def test_ns_partial_lame_authoritative_not_reported(
    fs, mock_dispatch_whois, configure_mock_resolver, monkeypatch
):
    import dns.rcode

    findings, _ = await _run_partial(
        fs, configure_mock_resolver, monkeypatch, [_response(dns.rcode.NOERROR, True)] * 2
    )
    assert not [f for f in findings if f["description"].startswith("Partially dangling")]


@pytest.mark.asyncio
async def test_ns_partial_lame_skips_unclaimable_providers(
    fs, mock_dispatch_whois, configure_mock_resolver, monkeypatch
):
    findings, queried = await _run_partial(
        fs, configure_mock_resolver, monkeypatch, [], nameservers=["ns1.live-provider.net", "ns2.live-provider.net"]
    )
    assert queried == []
    assert not [f for f in findings if f["description"].startswith("Partially dangling")]


# --- per-signature confidence ---


@pytest.mark.asyncio
async def test_ns_signature_confidence_override(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {"NS": ["ns1-09.azure-dns.com."]}}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=["ns1-09.azure-dns.com"])
    fs.create_file(
        "/tmp/signatures/test_confidence_ns.yml",
        contents="""
service_name: Confidence Test
source: self
mode: dns_nosoa
confidence: MEDIUM
identifiers:
  cnames: []
  ips: []
  nameservers: [azure-dns.com]
  not_cnames: []
matcher_rule: null
""",
    )
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns("bad.dns", signatures=signatures, dns_client=mock_resolver)
    findings = None
    if await baddns_ns.dispatch():
        findings = baddns_ns.analyze()
    sig_findings = [f.to_dict() for f in findings if f.to_dict()["signature"] == "Confidence Test"]
    assert sig_findings and sig_findings[0]["confidence"] == "MEDIUM"
