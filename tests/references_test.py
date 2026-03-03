import re
import pytest
import requests
import functools
from unittest.mock import patch

from baddns.modules.references import BadDNS_references
from baddns.lib.loader import load_signatures
from .helpers import mock_signature_load

mock_whois_unregistered = {
    "type": "error",
    "data": 'No match for "WORSE.DNS".\r\n>>> Last update of whois database: 2023-08-17T14:07:31Z <<<\r\n',
}

requests.adapters.BaseAdapter.send = functools.partialmethod(requests.adapters.BaseAdapter.send, verify=False)
requests.adapters.HTTPAdapter.send = functools.partialmethod(requests.adapters.HTTPAdapter.send, verify=False)
requests.Session.request = functools.partialmethod(requests.Session.request, verify=False)
requests.request = functools.partial(requests.request, verify=False)

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
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_unregistered], indirect=True)
async def test_references_cname_css(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
        mock_resolver = configure_mock_resolver(mock_data)
        mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
        signatures = load_signatures("/tmp/signatures")
        httpx_mock.add_response(
            url="http://bad.dns/",
            status_code=200,
            text=mock_references_http_css_cname,
        )
        target = "bad.dns"
        signatures = load_signatures("/tmp/signatures")
        baddns_references = BadDNS_references(target, signatures=signatures, dns_client=mock_resolver)
        findings = None
        if await baddns_references.dispatch():
            findings = baddns_references.analyze()
        assert not exit_mock.called

        expected = {
            "target": "bad.dns",
            "description": "Hijackable reference, CSS Include [css.baddnscdn.com]. Original Event: [CNAME unregistered]",
            "confidence": "CONFIRMED",
            "severity": "MEDIUM",
            "signature": "N/A",
            "indicator": "Whois Data",
            "trigger": "CSS Source: [http://css.baddnscdn.com/style.css], Original Trigger: [css.baddnscdn.com] Direct Mode: [True]",
            "module": "references",
        }
        assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_unregistered], indirect=True)
async def test_references_cname_js(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
        mock_resolver = configure_mock_resolver(mock_data)
        mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
        signatures = load_signatures("/tmp/signatures")
        httpx_mock.add_response(
            url="http://bad.dns/",
            status_code=200,
            text=mock_references_http_js_cname,
        )
        target = "bad.dns"
        signatures = load_signatures("/tmp/signatures")
        baddns_references = BadDNS_references(target, signatures=signatures, dns_client=mock_resolver)
        findings = None
        if await baddns_references.dispatch():
            findings = baddns_references.analyze()
        assert not exit_mock.called

        expected = {
            "target": "bad.dns",
            "description": "Hijackable reference, JS Include [js.baddnscdn.com]. Original Event: [CNAME unregistered]",
            "confidence": "CONFIRMED",
            "severity": "MEDIUM",
            "signature": "N/A",
            "indicator": "Whois Data",
            "trigger": "Javascript Source: [http://js.baddnscdn.com/script.js], Original Trigger: [js.baddnscdn.com] Direct Mode: [True]",
            "module": "references",
        }

        assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
async def test_references_direct_js(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"A": ["127.0.0.1"]}, "_NXDOMAIN": ["direct.azurewebsites.net"]}
        mock_resolver = configure_mock_resolver(mock_data)
        mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

        httpx_mock.add_response(
            url="http://bad.dns/",
            status_code=200,
            text=mock_references_http_js_direct,
        )
        target = "bad.dns"
        signatures = load_signatures("/tmp/signatures")
        baddns_references = BadDNS_references(target, signatures=signatures, dns_client=mock_resolver)
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
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
async def test_references_direct_css(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"A": ["127.0.0.1"]}, "_NXDOMAIN": ["direct.azurewebsites.net"]}
        mock_resolver = configure_mock_resolver(mock_data)
        mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

        httpx_mock.add_response(
            url="http://bad.dns/",
            status_code=200,
            text=mock_references_http_css_direct,
        )
        target = "bad.dns"
        signatures = load_signatures("/tmp/signatures")
        baddns_references = BadDNS_references(target, signatures=signatures, dns_client=mock_resolver)
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
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
async def test_references_direct_csp(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {
            "bad.dns": {"A": ["127.0.0.1"]},
            "_NXDOMAIN": ["direct.azurewebsites.net", "direct2.azurewebsites.net"],
        }
        mock_resolver = configure_mock_resolver(mock_data)
        mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

        httpx_mock.add_response(
            url="http://bad.dns/",
            status_code=200,
            text="OK",
            headers=mock_references_headers_csp,
        )
        target = "bad.dns"
        signatures = load_signatures("/tmp/signatures")
        baddns_references = BadDNS_references(target, signatures=signatures, dns_client=mock_resolver)
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
@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
async def test_references_direct_cors(
    fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver, cached_suffix_list
):
    with patch("sys.exit") as exit_mock:
        mock_data = {
            "bad.dns": {"A": ["127.0.0.1"]},
            "_NXDOMAIN": ["direct.azurewebsites.net", "direct2.azurewebsites.net"],
        }
        mock_resolver = configure_mock_resolver(mock_data)
        mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

        httpx_mock.add_response(
            url="http://bad.dns/",
            status_code=200,
            text="OK",
            headers=mock_references_headers_cors,
        )
        target = "bad.dns"
        signatures = load_signatures("/tmp/signatures")
        baddns_references = BadDNS_references(target, signatures=signatures, dns_client=mock_resolver)
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
