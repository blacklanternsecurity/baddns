import pytest
from baddns.modules import wildcard
from baddns.modules.wildcard import BadDNS_wildcard
from baddns.lib import dnsmanager
from baddns.lib.loader import load_signatures
from baddns.lib.signature import BadDNSSignature
from .helpers import mock_signature_load


_real_generate_random_label = dnsmanager.generate_random_label


@pytest.fixture(autouse=True)
def patch_random_label(monkeypatch):
    monkeypatch.setattr(dnsmanager, "generate_random_label", lambda: "baddns-test1234")


def test_generate_random_label():
    """The real generate_random_label returns a baddns- prefixed string."""
    label = _real_generate_random_label()
    assert label.startswith("baddns-")
    assert len(label) == 15


@pytest.mark.asyncio
async def test_wildcard_cname_nxdomain_signature_match(fs, mock_dispatch_whois, configure_mock_resolver):
    """Wildcard CNAME to NXDOMAIN service with signature match -> HIGH severity finding."""
    mock_data = {
        "baddns-test1234.bad.dns": {"CNAME": ["baddns.azurewebsites.net."]},
        "_NXDOMAIN": ["baddns.azurewebsites.net"],
    }
    mock_resolver = configure_mock_resolver(mock_data)

    target = "sub.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_wildcard.dispatch():
        findings = baddns_wildcard.analyze()

    assert findings
    expected = {
        "target": "sub.bad.dns",
        "description": "Wildcard CNAME detected at *.bad.dns. ALL subdomains of bad.dns are affected. Original Event: [Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)]",
        "confidence": "HIGH",
        "severity": "HIGH",
        "signature": "Microsoft Azure Takeover Detection",
        "indicator": "azurewebsites.net",
        "trigger": "*.bad.dns",
        "module": "WILDCARD",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_wildcard_no_wildcard_nxdomain(fs, mock_dispatch_whois, configure_mock_resolver):
    """No wildcard record (NXDOMAIN for random subdomain) -> dispatch returns False."""
    mock_data = {
        "_NXDOMAIN": ["baddns-test1234.bad.dns"],
    }
    mock_resolver = configure_mock_resolver(mock_data)

    target = "sub.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver)

    result = await baddns_wildcard.dispatch()
    assert result is False


@pytest.mark.asyncio
async def test_wildcard_a_record_only(fs, mock_dispatch_whois, configure_mock_resolver):
    """Wildcard resolves to A record only (no CNAME) -> dispatch returns False."""
    mock_data = {
        "baddns-test1234.bad.dns": {"A": ["1.2.3.4"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)

    target = "sub.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver)

    result = await baddns_wildcard.dispatch()
    assert result is False


@pytest.mark.asyncio
async def test_wildcard_target_is_registered_domain(fs, mock_dispatch_whois, configure_mock_resolver):
    """Target is already a registered domain (e.g. bad.dns) -> dispatch returns False."""
    mock_data = {}
    mock_resolver = configure_mock_resolver(mock_data)

    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver)

    result = await baddns_wildcard.dispatch()
    assert result is False


@pytest.mark.asyncio
async def test_wildcard_cname_resolves_not_vulnerable(fs, mock_dispatch_whois, mock_http, configure_mock_resolver):
    """Wildcard CNAME resolves to a healthy target -> no findings."""
    mock_data = {
        "baddns-test1234.bad.dns": {"CNAME": ["healthy.example.com."]},
        "healthy.example.com": {"A": ["1.2.3.4"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)

    target = "sub.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver, http_client=mock_http)

    findings = None
    if await baddns_wildcard.dispatch():
        findings = baddns_wildcard.analyze()

    assert not findings


@pytest.mark.asyncio
async def test_wildcard_deep_subdomain(fs, mock_dispatch_whois, configure_mock_resolver):
    """Deep subdomain (deep.sub.bad.dns) checks *.sub.bad.dns."""
    mock_data = {
        "baddns-test1234.sub.bad.dns": {"CNAME": ["baddns.azurewebsites.net."]},
        "_NXDOMAIN": ["baddns.azurewebsites.net"],
    }
    mock_resolver = configure_mock_resolver(mock_data)

    target = "deep.sub.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_wildcard.dispatch():
        findings = baddns_wildcard.analyze()

    assert findings
    expected = {
        "target": "deep.sub.bad.dns",
        "description": "Wildcard CNAME detected at *.sub.bad.dns. ALL subdomains of sub.bad.dns are affected. Original Event: [Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)]",
        "confidence": "HIGH",
        "severity": "HIGH",
        "signature": "Microsoft Azure Takeover Detection",
        "indicator": "azurewebsites.net",
        "trigger": "*.sub.bad.dns",
        "module": "WILDCARD",
    }
    assert any(expected == finding.to_dict() for finding in findings)


mock_whois_unregistered = {
    "type": "error",
    "data": 'No match for "WORSE.DNS".\r\n>>> Last update of whois database: 2023-08-17T14:07:31Z <<<\r\n',
}


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_unregistered], indirect=True)
async def test_wildcard_whois_unregistered(fs, mock_dispatch_whois, mock_http, configure_mock_resolver):
    """Wildcard CNAME to a domain that is unregistered per WHOIS -> CONFIRMED confidence."""
    mock_data = {
        "baddns-test1234.bad.dns": {"CNAME": ["worse.dns."]},
        "worse.dns": {"A": ["127.0.0.2"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)

    target = "sub.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver, http_client=mock_http)

    findings = None
    if await baddns_wildcard.dispatch():
        findings = baddns_wildcard.analyze()

    assert findings
    assert any(f.to_dict()["confidence"] == "CONFIRMED" for f in findings)
    assert any(f.to_dict()["severity"] == "HIGH" for f in findings)
    assert any(f.to_dict()["module"] == "WILDCARD" for f in findings)


@pytest.mark.asyncio
async def test_wildcard_generic_dangling_cname(fs, mock_dispatch_whois, configure_mock_resolver):
    """Wildcard CNAME to unknown NXDOMAIN service (no signature) -> MEDIUM confidence, GENERIC."""
    mock_data = {
        "baddns-test1234.bad.dns": {"CNAME": ["unknown.randomthing.net."]},
        "_NXDOMAIN": ["unknown.randomthing.net"],
    }
    mock_resolver = configure_mock_resolver(mock_data)

    target = "sub.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver)

    findings = None
    if await baddns_wildcard.dispatch():
        findings = baddns_wildcard.analyze()

    assert findings
    expected = {
        "target": "sub.bad.dns",
        "description": "Wildcard CNAME detected at *.bad.dns. ALL subdomains of bad.dns are affected. Original Event: [Dangling CNAME, possible subdomain takeover (NXDOMAIN technique)]",
        "confidence": "MEDIUM",
        "severity": "HIGH",
        "signature": "GENERIC",
        "indicator": "Generic Dangling CNAME",
        "trigger": "*.bad.dns",
        "module": "WILDCARD",
    }
    assert any(expected == finding.to_dict() for finding in findings)


NO_SUCH_BUCKET = "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message><BucketName>baddns-test1234</BucketName></Error>"


@pytest.fixture
def probed_parents(monkeypatch):
    """Records each parent the module sends a wildcard probe for."""
    parents = []
    real_probe = wildcard.probe_wildcard_cname

    async def recording_probe(parent, **kwargs):
        parents.append(parent)
        return await real_probe(parent, **kwargs)

    monkeypatch.setattr(wildcard, "probe_wildcard_cname", recording_probe)
    return parents


def _signature(identifier_type, value):
    sig = BadDNSSignature()
    sig.initialize(
        mode="dns_nxdomain",
        source="self",
        service_name="test",
        identifiers={"cnames": [{"type": identifier_type, "value": value}]},
    )
    return sig


@pytest.mark.asyncio
async def test_wildcard_s3_bucket_host_not_probed(fs, configure_mock_resolver, probed_parents):
    """An S3 bucket host must not probe *.s3.amazonaws.com as if it were the target's own zone (regression)."""
    mock_signature_load(fs, "nucleitemplates_aws-bucket-takeover.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(
        "haveafling.s3.amazonaws.com", signatures=signatures, dns_client=configure_mock_resolver({})
    )

    assert await baddns_wildcard.dispatch() is False
    assert probed_parents == []


@pytest.mark.asyncio
async def test_wildcard_to_unclaimed_s3_bucket(fs, mock_dispatch_whois, mock_http, configure_mock_resolver):
    """The owner's own zone carrying a wildcard CNAME to an unclaimed bucket is still a domain-wide finding."""
    mock_data = {
        "baddns-test1234.bad.dns": {"CNAME": ["dead-bucket.s3.amazonaws.com."]},
        "dead-bucket.s3.amazonaws.com": {"CNAME": ["s3-1-w.amazonaws.com."]},
        "s3-1-w.amazonaws.com": {"A": ["16.15.230.2"]},
    }
    mock_resolver = configure_mock_resolver(mock_data)
    mock_http.add_response(url="http://baddns-test1234.bad.dns/", status=404, body=NO_SUCH_BUCKET)

    target = "sub.bad.dns"
    mock_signature_load(fs, "nucleitemplates_aws-bucket-takeover.yml")
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=mock_resolver, http_client=mock_http)

    findings = None
    if await baddns_wildcard.dispatch():
        findings = baddns_wildcard.analyze()

    assert findings
    assert any(
        f.to_dict()["signature"] == "AWS Bucket Takeover Detection" and f.to_dict()["trigger"] == "*.bad.dns"
        for f in findings
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target, signature_file",
    [
        ("someapp.azurewebsites.net", "nucleitemplates_azure-takeover-detection.yml"),
        ("someuser.github.io", "dnsreaper_github_pages.yml"),
        ("bucket.s3.eu-central-1.wasabisys.com", "nucleitemplates_wasabi-bucket-takeover.yml"),
    ],
)
async def test_wildcard_skips_service_zones(fs, configure_mock_resolver, probed_parents, target, signature_file):
    """Any parent that is a signature's own service zone is skipped before probing, not just amazonaws.com."""
    mock_signature_load(fs, signature_file)
    signatures = load_signatures("/tmp/signatures")
    baddns_wildcard = BadDNS_wildcard(target, signatures=signatures, dns_client=configure_mock_resolver({}))

    assert await baddns_wildcard.dispatch() is False
    assert probed_parents == []


@pytest.mark.asyncio
async def test_wildcard_skips_service_zone_regex_identifier(configure_mock_resolver, probed_parents):
    """A service identified by a regex cname identifier is skipped too."""
    signatures = [_signature("regex", r"(^|\.)svc-zone\.net$")]
    baddns_wildcard = BadDNS_wildcard(
        "app.svc-zone.net", signatures=signatures, dns_client=configure_mock_resolver({})
    )

    assert await baddns_wildcard.dispatch() is False
    assert probed_parents == []


@pytest.mark.asyncio
async def test_wildcard_service_zone_label_boundary(configure_mock_resolver, probed_parents):
    """A zone that merely ends with a service domain's text (notamazonaws.com) is still probed."""
    signatures = [_signature("word", "amazonaws.com")]
    baddns_wildcard = BadDNS_wildcard(
        "sub.notamazonaws.com", signatures=signatures, dns_client=configure_mock_resolver({})
    )

    await baddns_wildcard.dispatch()
    assert probed_parents == ["notamazonaws.com"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target, expected",
    [
        ("example.co.uk", []),
        ("sub.example.co.uk", ["example.co.uk"]),
        ("a.b.example.com", ["b.example.com"]),
        ("sub.bad.dns", ["bad.dns"]),
    ],
)
async def test_wildcard_parent_stops_at_registrable_domain(configure_mock_resolver, probed_parents, target, expected):
    """The probe never climbs above the registrable domain into a public suffix."""
    baddns_wildcard = BadDNS_wildcard(target, signatures=[], dns_client=configure_mock_resolver({}))

    await baddns_wildcard.dispatch()
    assert probed_parents == expected
