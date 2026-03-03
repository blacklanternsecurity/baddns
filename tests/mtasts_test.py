import pytest
from baddns.modules.mtasts import BadDNS_mtasts
from baddns.lib.loader import load_signatures
from .helpers import mock_signature_load

mock_whois_unregistered = {
    "type": "error",
    "data": 'No match for "WORSE.DNS".\r\n>>> Last update of whois database: 2023-08-17T14:07:31Z <<<\r\n',
}

VALID_POLICY = """\
version: STSv1
mode: enforce
mx: mail.bad.dns
mx: *.bad.dns
max_age: 86400
"""

TESTING_POLICY = """\
version: STSv1
mode: testing
mx: mail.bad.dns
max_age: 86400
"""

MISMATCHED_POLICY = """\
version: STSv1
mode: enforce
mx: mail.other.dns
max_age: 86400
"""

POLICY_WITH_DANGLING_MX = """\
version: STSv1
mode: enforce
mx: mail.worse.dns
mx: mail.bad.dns
max_age: 86400
"""


@pytest.mark.asyncio
async def test_mtasts_no_txt_record(fs, mock_dispatch_whois, configure_mock_resolver):
    """No _mta-sts TXT record -> dispatch returns False, no findings."""
    mock_data = {"bad.dns": {}}
    mock_resolver = configure_mock_resolver(mock_data)

    baddns_mtasts = BadDNS_mtasts("bad.dns", dns_client=mock_resolver, signatures=[])
    result = await baddns_mtasts.dispatch()
    await baddns_mtasts.cleanup()

    assert result is False


@pytest.mark.asyncio
async def test_mtasts_txt_exists_no_sts(fs, mock_dispatch_whois, configure_mock_resolver):
    """TXT record exists but doesn't contain v=STSv1 -> dispatch returns False."""
    mock_data = {"_mta-sts.bad.dns": {"TXT": ["v=spf1 include:example.com ~all"]}}
    mock_resolver = configure_mock_resolver(mock_data)

    baddns_mtasts = BadDNS_mtasts("bad.dns", dns_client=mock_resolver, signatures=[])
    result = await baddns_mtasts.dispatch()
    await baddns_mtasts.cleanup()

    assert result is False


def test_mtasts_parse_policy_line_without_colon():
    """Lines without ':' in policy text should be skipped."""
    policy_text = "version: STSv1\nmode: enforce\ngarbage line\nmx: mail.bad.dns\nmax_age: 86400\n"
    result = BadDNS_mtasts._parse_policy(policy_text)
    assert result["version"] == "STSv1"
    assert result["mode"] == "enforce"
    assert result["mx"] == ["mail.bad.dns"]
    assert result["max_age"] == "86400"


@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
async def test_mtasts_dangling_cname_nxdomain(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    """TXT exists, mta-sts subdomain has CNAME to NXDOMAIN azure host -> takeover finding."""
    mock_data = {
        "_mta-sts.bad.dns": {"TXT": ["v=STSv1; id=abc123"]},
        "mta-sts.bad.dns": {"CNAME": ["baddns-sts.azurewebsites.net"]},
        "bad.dns": {"MX": ["mail.bad.dns"]},
        "_NXDOMAIN": ["baddns-sts.azurewebsites.net"],
    }
    mock_resolver = configure_mock_resolver(mock_data)
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")

    baddns_mtasts = BadDNS_mtasts("bad.dns", signatures=signatures, dns_client=mock_resolver)
    findings = None
    if await baddns_mtasts.dispatch():
        findings = baddns_mtasts.analyze()
    await baddns_mtasts.cleanup()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling mta-sts subdomain [mta-sts.bad.dns]. Original Event: [Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)]",
        "confidence": "HIGH",
        "severity": "HIGH",
        "signature": "Microsoft Azure Takeover Detection",
        "indicator": "azurewebsites.net",
        "trigger": "bad.dns",
        "module": "MTA-STS",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
async def test_mtasts_policy_unreachable(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    """TXT exists, policy unreachable (HTTP 404) -> orphaned config finding."""
    mock_data = {
        "_mta-sts.bad.dns": {"TXT": ["v=STSv1; id=abc123"]},
        "mta-sts.bad.dns": {"A": ["1.2.3.4"]},
        "bad.dns": {"MX": ["mail.bad.dns"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)

    httpx_mock.add_response(
        url="https://mta-sts.bad.dns/.well-known/mta-sts.txt",
        status_code=404,
    )

    baddns_mtasts = BadDNS_mtasts("bad.dns", signatures=[], dns_client=mock_resolver)
    findings = None
    if await baddns_mtasts.dispatch():
        findings = baddns_mtasts.analyze()
    await baddns_mtasts.cleanup()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Orphaned MTA-STS TXT record: _mta-sts.bad.dns exists but policy is unreachable (HTTP 404)",
        "confidence": "MODERATE",
        "severity": "MEDIUM",
        "signature": "MTA-STS",
        "indicator": "MTA-STS Policy Unreachable",
        "trigger": "_mta-sts.bad.dns",
        "module": "MTA-STS",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
async def test_mtasts_mx_mismatch_enforce(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    """TXT exists, valid policy in enforce mode, MX mismatch -> mismatch finding."""
    mock_data = {
        "_mta-sts.bad.dns": {"TXT": ["v=STSv1; id=abc123"]},
        "mta-sts.bad.dns": {"A": ["1.2.3.4"]},
        "bad.dns": {"MX": ["mail.bad.dns", "backup.bad.dns"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)

    httpx_mock.add_response(
        url="https://mta-sts.bad.dns/.well-known/mta-sts.txt",
        status_code=200,
        text=MISMATCHED_POLICY,
    )

    baddns_mtasts = BadDNS_mtasts("bad.dns", signatures=[], dns_client=mock_resolver)
    findings = None
    if await baddns_mtasts.dispatch():
        findings = baddns_mtasts.analyze()
    await baddns_mtasts.cleanup()

    assert findings
    mismatch_findings = [f for f in findings if "MX mismatch" in f.to_dict()["description"]]
    assert len(mismatch_findings) == 1
    finding_dict = mismatch_findings[0].to_dict()
    assert "mail.bad.dns" in finding_dict["description"]
    assert "backup.bad.dns" in finding_dict["description"]
    assert finding_dict["confidence"] == "MODERATE"
    assert finding_dict["severity"] == "MEDIUM"
    assert finding_dict["module"] == "MTA-STS"


@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
async def test_mtasts_mx_mismatch_testing_mode(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    """TXT exists, valid policy in testing mode, MX mismatch -> NO finding."""
    mock_data = {
        "_mta-sts.bad.dns": {"TXT": ["v=STSv1; id=abc123"]},
        "mta-sts.bad.dns": {"A": ["1.2.3.4"]},
        "bad.dns": {"MX": ["mail.bad.dns", "backup.bad.dns"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)

    httpx_mock.add_response(
        url="https://mta-sts.bad.dns/.well-known/mta-sts.txt",
        status_code=200,
        text=TESTING_POLICY,
    )

    baddns_mtasts = BadDNS_mtasts("bad.dns", signatures=[], dns_client=mock_resolver)
    findings = None
    if await baddns_mtasts.dispatch():
        findings = baddns_mtasts.analyze()
    await baddns_mtasts.cleanup()

    assert findings is not None
    mismatch_findings = [f for f in findings if "MX mismatch" in f.to_dict()["description"]]
    assert len(mismatch_findings) == 0


@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_unregistered], indirect=True)
async def test_mtasts_dangling_mx_domain_unregistered(
    fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver, cached_suffix_list
):
    """TXT exists, valid policy, MX domain unregistered -> WHOIS-based dangling MX finding."""
    mock_data = {
        "_mta-sts.bad.dns": {"TXT": ["v=STSv1; id=abc123"]},
        "mta-sts.bad.dns": {"A": ["1.2.3.4"]},
        "bad.dns": {"MX": ["mail.worse.dns"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)

    httpx_mock.add_response(
        url="https://mta-sts.bad.dns/.well-known/mta-sts.txt",
        status_code=200,
        text=POLICY_WITH_DANGLING_MX,
    )

    baddns_mtasts = BadDNS_mtasts("bad.dns", signatures=[], dns_client=mock_resolver)
    findings = None
    if await baddns_mtasts.dispatch():
        findings = baddns_mtasts.analyze()
    await baddns_mtasts.cleanup()

    assert findings
    # Filter specifically for MTA-STS policy mx domain findings (not CNAME-wrapped ones)
    whois_findings = [f for f in findings if "MTA-STS policy mx domain" in f.to_dict()["description"]]
    assert len(whois_findings) >= 1
    finding_dict = whois_findings[0].to_dict()
    assert finding_dict["confidence"] == "CONFIRMED"
    assert finding_dict["severity"] == "MEDIUM"
    assert finding_dict["indicator"] == "Whois Data"
    assert finding_dict["trigger"] == "mail.worse.dns"
    assert finding_dict["module"] == "MTA-STS"


@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
async def test_mtasts_all_correct(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    """TXT exists, valid policy, everything correct -> no findings."""
    mock_data = {
        "_mta-sts.bad.dns": {"TXT": ["v=STSv1; id=abc123"]},
        "mta-sts.bad.dns": {"A": ["1.2.3.4"]},
        "bad.dns": {"MX": ["mail.bad.dns"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)

    httpx_mock.add_response(
        url="https://mta-sts.bad.dns/.well-known/mta-sts.txt",
        status_code=200,
        text=VALID_POLICY,
    )

    baddns_mtasts = BadDNS_mtasts("bad.dns", signatures=[], dns_client=mock_resolver)
    findings = None
    if await baddns_mtasts.dispatch():
        findings = baddns_mtasts.analyze()
    await baddns_mtasts.cleanup()

    assert not findings
