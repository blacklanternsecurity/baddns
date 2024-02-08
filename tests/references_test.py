import pytest
import requests
import functools
from mock import patch

from baddns.modules.references import BadDNS_references
from baddns.lib.loader import load_signatures
from .helpers import mock_signature_load

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
    <script src="http://css.baddnscdn.com/script.js"></script>
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


@pytest.mark.asyncio
async def test_references_cname_css(fs, httpx_mock, configure_mock_resolver, cached_suffix_list):
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
            "description": "Hijackable reference, CSS Include. Original Event: [CNAME unregistered]",
            "confidence": "CONFIRMED",
            "signature": "N/A",
            "indicator": "Whois Data",
            "trigger": "CSS Source: [http://css.baddnscdn.com/style.css]",
            "module": "references",
        }
        assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_references_cname_js(fs, httpx_mock, configure_mock_resolver, cached_suffix_list):
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
            "description": "Hijackable reference, JS Include. Original Event: [CNAME unregistered]",
            "confidence": "CONFIRMED",
            "signature": "N/A",
            "indicator": "Whois Data",
            "trigger": "Javascript Source: [http://css.baddnscdn.com/script.js]",
            "module": "references",
        }
        assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_references_direct_js(fs, httpx_mock, configure_mock_resolver, cached_suffix_list):
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
            "description": "Hijackable reference, JS Include. Original Event: [Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)]",
            "confidence": "PROBABLE",
            "signature": "Microsoft Azure Takeover Detection",
            "indicator": "azurewebsites.net",
            "trigger": "Javascript Source: [http://direct.azurewebsites.net/script.js]",
            "module": "references",
        }
        assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_references_direct_css(fs, httpx_mock, configure_mock_resolver, cached_suffix_list):
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
            "description": "Hijackable reference, CSS Include. Original Event: [Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)]",
            "confidence": "PROBABLE",
            "signature": "Microsoft Azure Takeover Detection",
            "indicator": "azurewebsites.net",
            "trigger": "CSS Source: [http://direct.azurewebsites.net/style.css]",
            "module": "references",
        }
        assert any(expected == finding.to_dict() for finding in findings)
