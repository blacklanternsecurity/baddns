import pytest
from baddns.modules.cname import BadDNS_cname
from baddns.modules.mx import BadDNS_mx
from baddns.modules.ns import BadDNS_ns
from baddns.modules.nsec import BadDNS_nsec
from baddns.modules.references import BadDNS_references
from baddns.modules.txt import BadDNS_txt
from baddns.lib.loader import load_signatures
from .helpers import mock_signature_load


# CNAME line 158: IP-based signature check where IPs match
@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
async def test_cname_http_ip_signature_match(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    mock_data = {"bad.dns": {"CNAME": ["baddns.example.com"]}, "baddns.example.com": {"A": ["10.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)

    httpx_mock.add_response(url="http://bad.dns/", status_code=200, text="IP Matched Takeover Page")

    # Create a custom signature with IPs
    sig_content = """
service_name: IPTestService
mode: http
source: self
identifiers:
  cnames: []
  not_cnames: []
  ips:
    - "10.0.0.1"
  nameservers: []
matcher_rule:
  matchers:
  - type: word
    words:
    - IP Matched Takeover Page
    part: body
    condition: and
  matchers-condition: and
"""
    fake_dir = "/tmp/signatures"
    fs.create_dir(fake_dir)
    fs.create_file(f"{fake_dir}/ip_test.yml", contents=sig_content)

    signatures = load_signatures("/tmp/signatures")
    baddns_cname = BadDNS_cname("bad.dns", signatures=signatures, dns_client=mock_resolver)
    findings = None
    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()
    await baddns_cname.cleanup()
    assert findings
    assert any("IPTestService" in f.to_dict()["signature"] for f in findings)


# CNAME: No CNAME found, not self parent (line 40-42 branch)
@pytest.mark.asyncio
async def test_cname_no_cname_found(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_cname = BadDNS_cname(target, signatures=signatures, dns_client=mock_resolver)
    result = await baddns_cname.dispatch()
    assert result is False


# MX line 31: empty mx_record (continue branch)
@pytest.mark.asyncio
async def test_mx_empty_record(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {"MX": ["", "mail.bad.dns"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"
    baddns_mx = BadDNS_mx(target, dns_client=mock_resolver)
    result = await baddns_mx.dispatch()
    assert result is True


# MX: no MX records
@pytest.mark.asyncio
async def test_mx_no_records(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {}}
    mock_resolver = configure_mock_resolver(mock_data)
    baddns_mx = BadDNS_mx("bad.dns", dns_client=mock_resolver)
    result = await baddns_mx.dispatch()
    assert result is False


# NS lines 30-35: CNAME detected, follow chain
@pytest.mark.asyncio
async def test_ns_cname_chain_follow(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {"CNAME": ["target.bad.dns."]}, "target.bad.dns": {"SOA": ["ns1.bad.dns"]}}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=["ns1.danglingns.com"])
    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns(target, signatures=signatures, dns_client=mock_resolver)
    result = await baddns_ns.dispatch()
    assert result is True
    # Target should have been changed to the end of the CNAME chain
    assert baddns_ns.target == "target.bad.dns"


# NS: no NS and no SOA - empty findings
@pytest.mark.asyncio
async def test_ns_no_ns_records(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {}}
    mock_resolver = configure_mock_resolver(mock_data, mock_dnswalk_data=[])
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ns = BadDNS_ns("bad.dns", signatures=signatures, dns_client=mock_resolver)
    await baddns_ns.dispatch()
    result = baddns_ns.analyze()
    assert result is False


# NSEC lines 63-66: NSEC chain with single non-matching result
@pytest.mark.asyncio
async def test_nsec_single_nonmatching_result(fs, configure_mock_resolver):
    mock_data = {
        "bad.dns": {"NSEC": ["other.com"]},
        "other.com": {},
    }
    mock_resolver = configure_mock_resolver(mock_data)
    baddns_nsec = BadDNS_nsec("bad.dns", dns_client=mock_resolver)
    result = await baddns_nsec.dispatch()
    # Single non-matching result should abort
    assert result is False


# NSEC: wildcard protection (nsec_walk returns False)
@pytest.mark.asyncio
async def test_nsec_wildcard_protection(fs, configure_mock_resolver):
    mock_data = {
        "bad.dns": {"NSEC": ["bad.dns"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)
    baddns_nsec = BadDNS_nsec("bad.dns", dns_client=mock_resolver)
    result = await baddns_nsec.dispatch()
    assert result is False


# References: domain matching self target (line 148-149)
@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
async def test_references_self_domain_ignored(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)

    httpx_mock.add_response(
        url="http://bad.dns/",
        status_code=200,
        text='<script src="https://bad.dns/script.js"></script>',
    )

    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ref = BadDNS_references(target, signatures=signatures, dns_client=mock_resolver)
    await baddns_ref.dispatch()
    findings = baddns_ref.analyze()
    assert findings == []
    await baddns_ref.cleanup()


# References: extract_domains_body with relative URL (line 110-111)
@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
async def test_references_relative_url_skipped(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)

    httpx_mock.add_response(
        url="http://bad.dns/",
        status_code=200,
        text='<script src="/relative/path.js"></script>',
    )

    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ref = BadDNS_references(target, signatures=signatures, dns_client=mock_resolver)
    await baddns_ref.dispatch()
    findings = baddns_ref.analyze()
    assert findings == []
    await baddns_ref.cleanup()


# References: duplicate domain in headers (line 77)
@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
async def test_references_duplicate_header_domain(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    mock_data = {"bad.dns": {"A": ["127.0.0.1"]}, "evil.com": {"A": ["10.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)

    httpx_mock.add_response(
        url="http://bad.dns/",
        status_code=200,
        text="<html>body</html>",
        headers={"Content-Security-Policy": "default-src https://evil.com https://evil.com"},
    )

    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_ref = BadDNS_references(target, signatures=signatures, dns_client=mock_resolver)
    await baddns_ref.dispatch()
    await baddns_ref.cleanup()


# TXT line 84: IP address in TXT record (skipped)
@pytest.mark.asyncio
async def test_txt_ip_address_skipped(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {"TXT": ["v=spf1 ip4:192.168.1.1 ~all"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_txt = BadDNS_txt("bad.dns", signatures=signatures, dns_client=mock_resolver)
    result = await baddns_txt.dispatch()
    assert result is True
    await baddns_txt.cleanup()


# TXT line 122: non-direct cname findings
@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
async def test_txt_with_cname_findings(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    mock_data = {
        "bad.dns": {"TXT": ["v=spf1 include:vuln.somerandomthing.net ~all"]},
        "vuln.somerandomthing.net": {"CNAME": ["target.somerandomthing.net."]},
        "_NXDOMAIN": ["target.somerandomthing.net"],
    }
    mock_resolver = configure_mock_resolver(mock_data)
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_txt = BadDNS_txt("bad.dns", signatures=signatures, dns_client=mock_resolver)
    result = await baddns_txt.dispatch()
    assert result is True
    baddns_txt.analyze()
    await baddns_txt.cleanup()


# TXT: no TXT records
@pytest.mark.asyncio
async def test_txt_no_records(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {}}
    mock_resolver = configure_mock_resolver(mock_data)
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_txt = BadDNS_txt("bad.dns", signatures=signatures, dns_client=mock_resolver)
    result = await baddns_txt.dispatch()
    assert result is False
    await baddns_txt.cleanup()
