import os
import pytest
import pkg_resources
import requests

from baddns.lib.baddns import BadDNS_cname, WhoisManager
from .helpers import MockResolver

import ssl

# Disable SSL certificate verification
ssl._create_default_https_context = ssl._create_unverified_context

import functools

requests.adapters.BaseAdapter.send = functools.partialmethod(requests.adapters.BaseAdapter.send, verify=False)
requests.adapters.HTTPAdapter.send = functools.partialmethod(requests.adapters.HTTPAdapter.send, verify=False)
requests.Session.request = functools.partialmethod(requests.Session.request, verify=False)
requests.request = functools.partial(requests.request, verify=False)

# @pytest.fixture(autouse=True)
# def mock_tldextract(monkeypatch):

#     class FakeExtractResult:
#         def __init__(self):
#             # This is the static value you want to always return
#             self.registered_domain = "bad.dns"

#     def fake_extract(url):
#         return FakeExtractResult()

#     monkeypatch.setattr(tldextract, "extract", fake_extract)


@pytest.fixture()
def mock_dispatch_whois(monkeypatch):
    async def fake_dispatch_whois(self):
        return None

    monkeypatch.setattr(WhoisManager, "dispatchWHOIS", fake_dispatch_whois)


def mock_signature_load(fs, signature_filename):
    fake_dir = "/tmp/signatures"
    fs.create_dir(fake_dir)
    signatures_dir = pkg_resources.resource_filename("baddns", "signatures")
    signature_file = os.path.join(signatures_dir, signature_filename)
    fs.add_real_file(signature_file)
    os.symlink(signature_file, os.path.join(fake_dir, signature_filename))


@pytest.mark.asyncio
async def test_cname_dnsnxdomain_azure(fs, mock_dispatch_whois):
    mock_data = {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}

    mock_resolver = MockResolver(mock_data)

    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)

    finding = None
    if await baddns_cname.dispatch():
        finding = baddns_cname.analyze()

    assert finding
    assert finding == {
        "target": "bad.dns",
        "cname": "baddns.azurewebsites.net",
        "signature_name": "Microsoft Azure Takeover Detection",
        "matching_domain": "azurewebsites.net",
        "technique": "CNAME NXDOMAIN",
    }


@pytest.mark.asyncio
async def test_cname_dnsnxdomain_azure_negative(fs, mock_dispatch_whois):
    mock_data = {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "baddns.azurewebsites.net.": {"A": "127.0.0.1"}}

    mock_resolver = MockResolver(mock_data)
    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)

    finding = None
    if await baddns_cname.dispatch():
        finding = baddns_cname.analyze()

    assert not finding


@pytest.mark.asyncio
async def test_cname_http_bigcartel(fs, mock_dispatch_whois, httpx_mock):
    httpx_mock.add_response(
        url="http://bad.dns/",
        status_code=200,
        text="<h1>Oops! We couldn&#8217;t find that page.</h1>",
    )

    mock_data = {"bad.dns": {"CNAME": ["baddns.bigcartel.com"]}, "baddns.bigcartel.com": {"A": "127.0.0.1"}}

    mock_resolver = MockResolver(mock_data)
    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_bigcartel-takeover.yml")

    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)
    finding = None

    if await baddns_cname.dispatch():
        finding = baddns_cname.analyze()

    assert finding
    assert finding == {
        "target": "bad.dns",
        "cname": "baddns.bigcartel.com",
        "signature_name": "Bigcartel Takeover Detection",
        "technique": "HTTP String Match",
    }


@pytest.mark.asyncio
async def test_cname_http_bigcartel_negative(fs, mock_dispatch_whois, httpx_mock):
    mock_data = {"bad.dns": {"CNAME": ["baddns.bigcartel.com"]}, "_NXDOMAIN": ["baddns.bigcartel.com"]}

    mock_resolver = MockResolver(mock_data)
    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_bigcartel-takeover.yml")

    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)
    finding = None
    if await baddns_cname.dispatch():
        finding = baddns_cname.analyze()
    assert not finding
