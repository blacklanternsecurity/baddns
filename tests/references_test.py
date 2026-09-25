import re
import pytest
from unittest.mock import patch

from baddns.modules.references import BadDNS_references
from baddns.lib.loader import load_signatures
from .helpers import mock_signature_load

mock_whois_unregistered = {
    "type": "error",
    "data": 'No match for "WORSE.DNS".\r\n>>> Last update of whois database: 2023-08-17T14:07:31Z <<<\r\n',
}

mock_references_http_css_cname = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Test Page</title>
    <link rel="stylesheet" href="http://css.baddnscdn.com/style.css">
</head><body><h1>Hello, World!</h1></body></html>
"""

mock_references_http_css_direct = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Test Page</title>
    <link rel="stylesheet" href="http://direct.azurewebsites.net/style.css">
</head><body><h1>Hello, World!</h1></body></html>
"""

mock_references_http_js_cname = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Test Page</title>

</head>
<body>
    <h1>Hello, World!</h1>
    <script src="http://js.baddnscdn.com/script.js"></script>
</body>
</html>
"""

mock_references_http_js_direct = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Test Page</title>

</head>
<body>
    <h1>Hello, World!</h1>
    <script src="http://direct.azurewebsites.net/script.js"></script>
</body>
</html>
"""

mock_references_headers_csp = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' direct.azurewebsites.net http://direct2.azurewebsites.net; "
        "img-src 'self' direct.azurewebsites.net http://direct2.azurewebsites.net; "
        "connect-src 'self' direct.azurewebsites.net http://direct2.azurewebsites.net;"
    ),
    "Content-Type": "text/html; charset=UTF-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}

mock_references_headers_cors = {
    "Server": "Apache/2.4.52 (Ubuntu)",
    "Access-Control-Allow-Origin": "https://direct.azurewebsites.net",
    "Content-Length": "2",
}


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_unregistered], indirect=True)
async def test_references_cname_css(fs, mock_dispatch_whois, mock_http, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
        mock_resolver = configure_mock_resolver(mock_data)
        mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
        signatures = load_signatures("/tmp/signatures")
        mock_http.add_response(
            url="http://bad.dns/",
            status=200,
            body=mock_references_http_css_cname,
        )
        target = "bad.dns"
        signatures = load_signatures("/tmp/signatures")
        baddns_references = BadDNS_references(
            target, signatures=signatures, dns_client=mock_resolver, http_client=mock_http
        )
        findings = None
        if await baddns_references.dispatch():
            findings = baddns_references.analyze()
        assert not exit_mock.called

        expected = {
            "target": "bad.dns",
            "description": "Hijackable reference, CSS Include [css.baddnscdn.com]. Original Event: [CNAME unregistered]",
            "confidence": "CONFIRMED",
            "severity": "MEDIUM",
            "signature": "CNAME Takeover",
            "indicator": "Whois Data",
            "trigger": "CSS Source: [http://css.baddnscdn.com/style.css], Original Trigger: [css.baddnscdn.com] Direct Mode: [True]",
            "module": "references",
        }
        assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_unregistered], indirect=True)
async def test_references_cname_js(fs, mock_dispatch_whois, mock_http, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
        mock_resolver = configure_mock_resolver(mock_data)
        mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
        signatures = load_signatures("/tmp/signatures")
        mock_http.add_response(
            url="http://bad.dns/",
            status=200,
            body=mock_references_http_js_cname,
        )
        target = "bad.dns"
        signatures = load_signatures("/tmp/signatures")
        baddns_references = BadDNS_references(
            target, signatures=signatures, dns_client=mock_resolver, http_client=mock_http
        )
        findings = None
        if await baddns_references.dispatch():
            findings = baddns_references.analyze()
        assert not exit_mock.called

        expected = {
            "target": "bad.dns",
            "description": "Hijackable reference, JS Include [js.baddnscdn.com]. Original Event: [CNAME unregistered]",
            "confidence": "CONFIRMED",
            "severity": "MEDIUM",
            "signature": "CNAME Takeover",
            "indicator": "Whois Data",
            "trigger": "Javascript Source: [http://js.baddnscdn.com/script.js], Original Trigger: [js.baddnscdn.com] Direct Mode: [True]",
            "module": "references",
        }

        assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_references_direct_js(fs, mock_dispatch_whois, mock_http, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"A": ["127.0.0.1"]}, "_NXDOMAIN": ["direct.azurewebsites.net"]}
        mock_resolver = configure_mock_resolver(mock_data)
        mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

        mock_http.add_response(
            url="http://bad.dns/",
            status=200,
            body=mock_references_http_js_direct,
        )
        target = "bad.dns"
        signatures = load_signatures("/tmp/signatures")
        baddns_references = BadDNS_references(
            target, signatures=signatures, dns_client=mock_resolver, http_client=mock_http
        )
        findings = None
        if await baddns_references.dispatch():
            findings = baddns_references.analyze()
        assert not exit_mock.called

        expected = {
            "target": "bad.dns",
            "description": "Hijackable reference, JS Include [direct.azurewebsites.net]. Original Event: [Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)]",
            "confidence": "HIGH",
            "severity": "MEDIUM",
            "signature": "Microsoft Azure Takeover Detection",
            "indicator": "azurewebsites.net",
            "trigger": "Javascript Source: [http://direct.azurewebsites.net/script.js], Original Trigger: [self] Direct Mode: [True]",
            "module": "references",
        }
        assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_references_direct_css(fs, mock_dispatch_whois, mock_http, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"A": ["127.0.0.1"]}, "_NXDOMAIN": ["direct.azurewebsites.net"]}
        mock_resolver = configure_mock_resolver(mock_data)
        mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

        mock_http.add_response(
            url="http://bad.dns/",
            status=200,
            body=mock_references_http_css_direct,
        )
        target = "bad.dns"
        signatures = load_signatures("/tmp/signatures")
        baddns_references = BadDNS_references(
            target, signatures=signatures, dns_client=mock_resolver, http_client=mock_http
        )
        findings = None
        if await baddns_references.dispatch():
            findings = baddns_references.analyze()
        assert not exit_mock.called

        expected = {
            "target": "bad.dns",
            "description": "Hijackable reference, CSS Include [direct.azurewebsites.net]. Original Event: [Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)]",
            "confidence": "HIGH",
            "severity": "MEDIUM",
            "signature": "Microsoft Azure Takeover Detection",
            "indicator": "azurewebsites.net",
            "trigger": "CSS Source: [http://direct.azurewebsites.net/style.css], Original Trigger: [self] Direct Mode: [True]",
            "module": "references",
        }

        assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_references_direct_csp(fs, mock_dispatch_whois, mock_http, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {
            "bad.dns": {"A": ["127.0.0.1"]},
            "_NXDOMAIN": ["direct.azurewebsites.net", "direct2.azurewebsites.net"],
        }
        mock_resolver = configure_mock_resolver(mock_data)
        mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

        mock_http.add_response(
            url="http://bad.dns/",
            status=200,
            body="OK",
            headers=mock_references_headers_csp,
        )
        target = "bad.dns"
        signatures = load_signatures("/tmp/signatures")
        baddns_references = BadDNS_references(
            target, signatures=signatures, dns_client=mock_resolver, http_client=mock_http
        )
        findings = None
        if await baddns_references.dispatch():
            findings = baddns_references.analyze()
        assert not exit_mock.called

        expected_1 = {
            "target": "bad.dns",
            "description": "Hijackable reference, CSP domain [direct.azurewebsites.net]. Original Event: [Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)]",
            "confidence": "HIGH",
            "severity": "MEDIUM",
            "signature": "Microsoft Azure Takeover Detection",
            "indicator": "azurewebsites.net",
            "trigger": "Content-Security-Policy Header: [direct.azurewebsites.net], Original Trigger: [self] Direct Mode: [True]",
            "module": "references",
        }
        expected_2 = {
            "target": "bad.dns",
            "description": "Hijackable reference, CSP domain [direct2.azurewebsites.net]. Original Event: [Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)]",
            "confidence": "HIGH",
            "severity": "MEDIUM",
            "signature": "Microsoft Azure Takeover Detection",
            "indicator": "azurewebsites.net",
            "trigger": "Content-Security-Policy Header: [http://direct2.azurewebsites.net], Original Trigger: [self] Direct Mode: [True]",
            "module": "references",
        }

        assert any(expected_1 == finding.to_dict() for finding in findings)
        assert any(expected_2 == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_references_direct_cors(fs, mock_dispatch_whois, mock_http, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {
            "bad.dns": {"A": ["127.0.0.1"]},
            "_NXDOMAIN": ["direct.azurewebsites.net", "direct2.azurewebsites.net"],
        }
        mock_resolver = configure_mock_resolver(mock_data)
        mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

        mock_http.add_response(
            url="http://bad.dns/",
            status=200,
            body="OK",
            headers=mock_references_headers_cors,
        )
        target = "bad.dns"
        signatures = load_signatures("/tmp/signatures")
        baddns_references = BadDNS_references(
            target, signatures=signatures, dns_client=mock_resolver, http_client=mock_http
        )
        findings = None
        if await baddns_references.dispatch():
            findings = baddns_references.analyze()
        assert not exit_mock.called

        expected = {
            "target": "bad.dns",
            "description": "Hijackable reference, CORS header domain [direct.azurewebsites.net]. Original Event: [Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)]",
            "confidence": "HIGH",
            "severity": "MEDIUM",
            "signature": "Microsoft Azure Takeover Detection",
            "indicator": "azurewebsites.net",
            "trigger": "Access-Control-Allow-Origin Header: [https://direct.azurewebsites.net], Original Trigger: [self] Direct Mode: [True]",
            "module": "references",
        }

        assert any(expected == finding.to_dict() for finding in findings)


def test_references_extract_domains_empty_group(configure_mock_resolver):
    """Regex match with empty group(1) should hit 'Failed to extract domain' branch."""
    mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    instance = BadDNS_references("bad.dns", signatures=[], dns_client=mock_resolver)

    # Replace regex_domain_url with one that produces empty group(1)
    instance.regex_domain_url = re.compile(r"()(\S+)")
    header_regex = re.compile(r"TestHeader: (.+?)\|")
    results = instance.extract_domains_headers("TestHeader", header_regex, "TestHeader: something.com|", "test desc")
    assert results == []


# ---------------------------------------------------------------------------
# Bucket reference detection tests
# ---------------------------------------------------------------------------

mock_body_s3_path = """
<!DOCTYPE html>
<html><body>
<img src="https://s3.amazonaws.com/dead-bucket-abc/logo.png">
</body></html>
"""

mock_body_s3_vhost = """
<!DOCTYPE html>
<html><body>
<img src="https://dead-bucket-abc.s3.us-east-1.amazonaws.com/logo.png">
</body></html>
"""

mock_body_s3_region_path = """
<!DOCTYPE html>
<html><body>
<video src="https://s3.eu-west-1.amazonaws.com/dead-bucket-abc/video.mp4"></video>
</body></html>
"""

mock_body_gcs = """
<!DOCTYPE html>
<html><body>
<img src="https://storage.googleapis.com/dead-gcs-bucket/icon.svg">
</body></html>
"""

mock_body_s3_existing = """
<!DOCTYPE html>
<html><body>
<img src="https://s3.amazonaws.com/existing-bucket/logo.png">
</body></html>
"""

mock_body_multiple_buckets = """
<!DOCTYPE html>
<html><body>
<img src="https://s3.amazonaws.com/dead-one/a.png">
<img src="https://s3.amazonaws.com/dead-two/b.png">
<img src="https://s3.amazonaws.com/alive-one/c.png">
</body></html>
"""

mock_body_media_tags = """
<!DOCTYPE html>
<html><body>
<iframe src="https://s3.amazonaws.com/dead-iframe-bucket/page.html"></iframe>
<audio src="https://s3.amazonaws.com/dead-audio-bucket/track.mp3"></audio>
<source src="https://s3.amazonaws.com/dead-source-bucket/clip.webm">
<embed src="https://s3.amazonaws.com/dead-embed-bucket/widget.swf">
</body></html>
"""


class TestBucketExtraction:
    """Unit tests for extract_bucket_refs — no HTTP, no async."""

    def test_s3_path_style(self, configure_mock_resolver):
        mock_resolver = configure_mock_resolver({"bad.dns": {"A": ["127.0.0.1"]}})
        inst = BadDNS_references("bad.dns", signatures=[], dns_client=mock_resolver)
        refs = inst.extract_bucket_refs(mock_body_s3_path)
        assert len(refs) == 1
        assert refs[0]["provider"] == "aws-s3"
        assert refs[0]["bucket"] == "dead-bucket-abc"

    def test_s3_vhost_style(self, configure_mock_resolver):
        mock_resolver = configure_mock_resolver({"bad.dns": {"A": ["127.0.0.1"]}})
        inst = BadDNS_references("bad.dns", signatures=[], dns_client=mock_resolver)
        refs = inst.extract_bucket_refs(mock_body_s3_vhost)
        assert len(refs) == 1
        assert refs[0]["provider"] == "aws-s3"
        assert refs[0]["bucket"] == "dead-bucket-abc"

    def test_s3_region_path(self, configure_mock_resolver):
        mock_resolver = configure_mock_resolver({"bad.dns": {"A": ["127.0.0.1"]}})
        inst = BadDNS_references("bad.dns", signatures=[], dns_client=mock_resolver)
        refs = inst.extract_bucket_refs(mock_body_s3_region_path)
        assert len(refs) == 1
        assert refs[0]["bucket"] == "dead-bucket-abc"

    def test_gcs_path_style(self, configure_mock_resolver):
        mock_resolver = configure_mock_resolver({"bad.dns": {"A": ["127.0.0.1"]}})
        inst = BadDNS_references("bad.dns", signatures=[], dns_client=mock_resolver)
        refs = inst.extract_bucket_refs(mock_body_gcs)
        assert len(refs) == 1
        assert refs[0]["provider"] == "gcs"
        assert refs[0]["bucket"] == "dead-gcs-bucket"

    def test_deduplication(self, configure_mock_resolver):
        mock_resolver = configure_mock_resolver({"bad.dns": {"A": ["127.0.0.1"]}})
        inst = BadDNS_references("bad.dns", signatures=[], dns_client=mock_resolver)
        body = """
        <img src="https://s3.amazonaws.com/my-bucket/a.png">
        <img src="https://s3.amazonaws.com/my-bucket/b.png">
        <img src="https://my-bucket.s3.amazonaws.com/c.png">
        """
        refs = inst.extract_bucket_refs(body)
        assert len(refs) == 1

    def test_no_bucket_urls(self, configure_mock_resolver):
        mock_resolver = configure_mock_resolver({"bad.dns": {"A": ["127.0.0.1"]}})
        inst = BadDNS_references("bad.dns", signatures=[], dns_client=mock_resolver)
        refs = inst.extract_bucket_refs("<html><body><img src='https://cdn.example.com/img.png'></body></html>")
        assert refs == []


class TestBucketClaimable:
    """Unit tests for the _is_claimable static method."""

    def test_s3_nosuchbucket(self):
        assert BadDNS_references._is_claimable("aws-s3", 404, "<Error><Code>NoSuchBucket</Code></Error>")

    def test_s3_exists_403(self):
        assert not BadDNS_references._is_claimable("aws-s3", 403, "AccessDenied")

    def test_s3_exists_200(self):
        assert not BadDNS_references._is_claimable("aws-s3", 200, "ListBucketResult")

    def test_gcs_bucketnotfound(self):
        assert BadDNS_references._is_claimable("gcs", 404, "BucketNotFound")

    def test_gcs_exists(self):
        assert not BadDNS_references._is_claimable("gcs", 200, "OK")


@pytest.mark.asyncio
async def test_references_bucket_s3_claimable(
    fs, mock_dispatch_whois, mock_http, configure_mock_resolver, cached_suffix_list
):
    """S3 path-style bucket URL in an img tag — bucket is gone, should produce a finding."""
    mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)

    mock_http.add_response(url="http://bad.dns/", status=200, body=mock_body_s3_path)
    mock_http.add_response(
        url="https://s3.amazonaws.com/dead-bucket-abc/",
        status=404,
        body="<Error><Code>NoSuchBucket</Code><BucketName>dead-bucket-abc</BucketName></Error>",
    )

    baddns_ref = BadDNS_references("bad.dns", signatures=[], dns_client=mock_resolver, http_client=mock_http)
    assert await baddns_ref.dispatch()
    findings = baddns_ref.analyze()
    assert len(findings) == 1
    f = findings[0].to_dict()
    assert f["signature"] == "S3 Bucket Takeover"
    assert f["indicator"] == "dead-bucket-abc"
    assert f["confidence"] == "CONFIRMED"
    assert f["target"] == "bad.dns"
    await baddns_ref.cleanup()


@pytest.mark.asyncio
async def test_references_bucket_s3_vhost_claimable(
    fs, mock_dispatch_whois, mock_http, configure_mock_resolver, cached_suffix_list
):
    """S3 vhost-style bucket URL — bucket is gone."""
    mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)

    mock_http.add_response(url="http://bad.dns/", status=200, body=mock_body_s3_vhost)
    mock_http.add_response(
        url="https://s3.amazonaws.com/dead-bucket-abc/",
        status=404,
        body="<Error><Code>NoSuchBucket</Code></Error>",
    )

    baddns_ref = BadDNS_references("bad.dns", signatures=[], dns_client=mock_resolver, http_client=mock_http)
    assert await baddns_ref.dispatch()
    findings = baddns_ref.analyze()
    assert len(findings) == 1
    assert findings[0].to_dict()["signature"] == "S3 Bucket Takeover"
    await baddns_ref.cleanup()


@pytest.mark.asyncio
async def test_references_bucket_gcs_claimable(
    fs, mock_dispatch_whois, mock_http, configure_mock_resolver, cached_suffix_list
):
    """GCS path-style bucket URL — bucket is gone."""
    mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)

    mock_http.add_response(url="http://bad.dns/", status=200, body=mock_body_gcs)
    mock_http.add_response(
        url="https://storage.googleapis.com/dead-gcs-bucket/",
        status=404,
        body='{"error": {"code": 404, "message": "BucketNotFound"}}',
    )

    baddns_ref = BadDNS_references("bad.dns", signatures=[], dns_client=mock_resolver, http_client=mock_http)
    assert await baddns_ref.dispatch()
    findings = baddns_ref.analyze()
    assert len(findings) == 1
    f = findings[0].to_dict()
    assert f["signature"] == "GCS Bucket Takeover"
    assert f["indicator"] == "dead-gcs-bucket"
    await baddns_ref.cleanup()


@pytest.mark.asyncio
async def test_references_bucket_s3_exists(
    fs, mock_dispatch_whois, mock_http, configure_mock_resolver, cached_suffix_list
):
    """S3 bucket exists (403) — no finding."""
    mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)

    mock_http.add_response(url="http://bad.dns/", status=200, body=mock_body_s3_existing)
    mock_http.add_response(
        url="https://s3.amazonaws.com/existing-bucket/",
        status=403,
        body="<Error><Code>AccessDenied</Code></Error>",
    )

    baddns_ref = BadDNS_references("bad.dns", signatures=[], dns_client=mock_resolver, http_client=mock_http)
    assert await baddns_ref.dispatch()
    findings = baddns_ref.analyze()
    assert len(findings) == 0
    await baddns_ref.cleanup()


@pytest.mark.asyncio
async def test_references_bucket_multiple_mixed(
    fs, mock_dispatch_whois, mock_http, configure_mock_resolver, cached_suffix_list
):
    """Multiple buckets: two dead, one alive — should produce exactly two findings."""
    mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)

    mock_http.add_response(url="http://bad.dns/", status=200, body=mock_body_multiple_buckets)
    mock_http.add_response(
        url="https://s3.amazonaws.com/dead-one/",
        status=404,
        body="<Error><Code>NoSuchBucket</Code></Error>",
    )
    mock_http.add_response(
        url="https://s3.amazonaws.com/dead-two/",
        status=404,
        body="<Error><Code>NoSuchBucket</Code></Error>",
    )
    mock_http.add_response(
        url="https://s3.amazonaws.com/alive-one/",
        status=403,
        body="AccessDenied",
    )

    baddns_ref = BadDNS_references("bad.dns", signatures=[], dns_client=mock_resolver, http_client=mock_http)
    assert await baddns_ref.dispatch()
    findings = baddns_ref.analyze()
    assert len(findings) == 2
    indicators = {f.to_dict()["indicator"] for f in findings}
    assert indicators == {"dead-one", "dead-two"}
    await baddns_ref.cleanup()


@pytest.mark.asyncio
async def test_references_bucket_media_tags(
    fs, mock_dispatch_whois, mock_http, configure_mock_resolver, cached_suffix_list
):
    """iframe, audio, source, embed tags all get checked."""
    mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)

    mock_http.add_response(url="http://bad.dns/", status=200, body=mock_body_media_tags)
    for bucket in ("dead-iframe-bucket", "dead-audio-bucket", "dead-source-bucket", "dead-embed-bucket"):
        mock_http.add_response(
            url=f"https://s3.amazonaws.com/{bucket}/",
            status=404,
            body="<Error><Code>NoSuchBucket</Code></Error>",
        )

    baddns_ref = BadDNS_references("bad.dns", signatures=[], dns_client=mock_resolver, http_client=mock_http)
    assert await baddns_ref.dispatch()
    findings = baddns_ref.analyze()
    assert len(findings) == 4
    await baddns_ref.cleanup()


@pytest.mark.asyncio
async def test_references_no_buckets_in_page(
    fs, mock_dispatch_whois, mock_http, configure_mock_resolver, cached_suffix_list
):
    """Page with no bucket URLs — bucket_findings stays empty, no crash."""
    mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)

    mock_http.add_response(url="http://bad.dns/", status=200, body="<html><body>Hello</body></html>")

    baddns_ref = BadDNS_references("bad.dns", signatures=[], dns_client=mock_resolver, http_client=mock_http)
    assert await baddns_ref.dispatch()
    findings = baddns_ref.analyze()
    assert len(findings) == 0
    await baddns_ref.cleanup()
