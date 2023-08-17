import pytest
import requests
import datetime

from baddns.lib.baddns import BadDNS_cname, WhoisManager
from .helpers import MockResolver, mock_signature_load

import ssl

# Disable SSL certificate verification
ssl._create_default_https_context = ssl._create_unverified_context

import functools

requests.adapters.BaseAdapter.send = functools.partialmethod(requests.adapters.BaseAdapter.send, verify=False)
requests.adapters.HTTPAdapter.send = functools.partialmethod(requests.adapters.HTTPAdapter.send, verify=False)
requests.Session.request = functools.partialmethod(requests.Session.request, verify=False)
requests.request = functools.partial(requests.request, verify=False)


@pytest.fixture()
def mock_dispatch_whois(request, monkeypatch):
    value = getattr(request, "param", None)

    async def fake_dispatch_whois(self):
        print(f"Running mock_dispatch_whois with value: [{value}]")
        self.whois_result = value

    monkeypatch.setattr(WhoisManager, "dispatchWHOIS", fake_dispatch_whois)


@pytest.mark.asyncio
async def test_cname_dnsnxdomain_azure(fs, mock_dispatch_whois):
    mock_data = {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}

    mock_resolver = MockResolver(mock_data)

    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)

    findings = None
    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()

    assert findings
    assert {
        "target": "bad.dns",
        "cnames": ["baddns.azurewebsites.net"],
        "signature_name": "Microsoft Azure Takeover Detection",
        "matching_domain": "azurewebsites.net",
        "technique": "CNAME NXDOMAIN",
    } in findings


@pytest.mark.asyncio
async def test_cname_dnsnxdomain_generic(fs, mock_dispatch_whois):
    mock_data = {"bad.dns": {"CNAME": ["baddns.somerandomthing.net."]}, "_NXDOMAIN": ["baddns.somerandomthing.net"]}

    mock_resolver = MockResolver(mock_data)

    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)

    findings = None
    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()

    assert findings
    assert {
        "target": "bad.dns",
        "cnames": ["baddns.somerandomthing.net"],
        "signature_name": "Generic Dangling CNAME",
        "matching_domain": None,
        "technique": "CNAME NXDOMAIN",
    } in findings


@pytest.mark.asyncio
async def test_cname_dnsnxdomain_azure_negative(fs, mock_dispatch_whois):
    mock_data = {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "baddns.azurewebsites.net.": {"A": "127.0.0.1"}}

    mock_resolver = MockResolver(mock_data)
    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)

    findings = None
    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()

    assert not findings


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
    findings = None

    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()

    assert findings
    assert {
        "target": "bad.dns",
        "cnames": ["baddns.bigcartel.com"],
        "signature_name": "Bigcartel Takeover Detection",
        "technique": "HTTP String Match",
    } in findings


@pytest.mark.asyncio
async def test_cname_http_bigcartel_negative(fs, mock_dispatch_whois, httpx_mock):
    mock_data = {"bad.dns": {"CNAME": ["baddns.bigcartel.com"]}, "_NXDOMAIN": ["baddns.bigcartel.com"]}

    mock_resolver = MockResolver(mock_data)
    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_bigcartel-takeover.yml")

    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)
    findings = None
    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()
    assert findings
    assert "Generic" in findings[0]["signature_name"]


@pytest.mark.asyncio
async def test_cname_chainedcname_nxdomain(fs, mock_dispatch_whois, httpx_mock):
    mock_data = {
        "chain.bad.dns": {"CNAME": ["chain2.bad.dns."]},
        "chain2.bad.dns": {"CNAME": ["baddns.azurewebsites.net."]},
        "_NXDOMAIN": ["baddns.azurewebsites.net"],
    }

    mock_resolver = MockResolver(mock_data)

    target = "chain.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)

    findings = None
    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()

    assert findings
    assert {
        "target": "chain.bad.dns",
        "cnames": ["chain2.bad.dns", "baddns.azurewebsites.net"],
        "signature_name": "Microsoft Azure Takeover Detection",
        "matching_domain": "azurewebsites.net",
        "technique": "CNAME NXDOMAIN",
    } in findings


whois_mock_expired = {
    "type": "response",
    "data": {
        "domain_name": ["WORSE.DNS", "worse.dns"],
        "registrar": "Google LLC",
        "whois_server": "whois.google.com",
        "referral_url": None,
        "updated_date": datetime.datetime(2022, 4, 26, 17, 5, 40),
        "creation_date": datetime.datetime(2020, 4, 25, 15, 56, 10),
        "expiration_date": datetime.datetime(2023, 2, 25, 15, 56, 10),
        "name_servers": [
            "NS-CLOUD-B1.GOOGLEDOMAINS.COM",
            "NS-CLOUD-B2.GOOGLEDOMAINS.COM",
            "NS-CLOUD-B3.GOOGLEDOMAINS.COM",
            "NS-CLOUD-B4.GOOGLEDOMAINS.COM",
        ],
        "status": [
            "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
            "clientTransferProhibited https://www.icann.org/epp#clientTransferProhibited",
        ],
        "emails": "registrar-abuse@google.com",
        "dnssec": "unsigned",
        "name": "Contact Privacy Inc. Customer 7151571251",
        "org": "Contact Privacy Inc. Customer 7151571251",
        "address": "96 Mowat Ave",
        "city": "Toronto",
        "state": "ON",
        "registrant_postal_code": "M4K 3K1",
        "country": "CA",
    },
}


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_dispatch_whois", [whois_mock_expired], indirect=True)
async def test_cname_whois_expired(fs, mock_dispatch_whois, httpx_mock):
    mock_data = {
        "bad.dns": {"CNAME": ["worse.dns."]},
        "_NXDOMAIN": ["worse.dns"],
    }

    mock_resolver = MockResolver(mock_data)
    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)
    findings = None
    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()

    assert findings
    assert {
        "target": "bad.dns",
        "cnames": ["worse.dns"],
        "signature_name": None,
        "matching_domain": None,
        "technique": "CNAME Base Domain Expired",
        "expiration_date": "2023-02-25 15:56:10",
    } in findings


mock_whois_unregistered = {
    "type": "error",
    "data": "No match for \"WORSE.DNS\".\r\n>>> Last update of whois database: 2023-08-17T14:07:31Z <<<\r\n\r\nNOTICE: The expiration date displayed in this record is the date the\r\nregistrar's sponsorship of the domain name registration in the registry is\r\ncurrently set to expire. This date does not necessarily reflect the expiration\r\ndate of the domain name registrant's agreement with the sponsoring\r\nregistrar.  Users may consult the sponsoring registrar's Whois database to\r\nview the registrar's reported date of expiration for this registration.\r\n\r\nTERMS OF USE: You are not authorized to access or query our Whois\r\ndatabase through the use of electronic processes that are high-volume and\r\nautomated except as reasonably necessary to register domain names or\r\nmodify existing registrations; the Data in VeriSign Global Registry\r\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\r\ninformation purposes only, and to assist persons in obtaining information\r\nabout or related to a domain name registration record. VeriSign does not\r\nguarantee its accuracy. By submitting a Whois query, you agree to abide\r\nby the following terms of use: You agree that you may use this Data only\r\nfor lawful purposes and that under no circumstances will you use this Data\r\nto: (1) allow, enable, or otherwise support the transmission of mass\r\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\r\nor facsimile; or (2) enable high volume, automated, electronic processes\r\nthat apply to VeriSign (or its computer systems). The compilation,\r\nrepackaging, dissemination or other use of this Data is expressly\r\nprohibited without the prior written consent of VeriSign. You agree not to\r\nuse electronic processes that are automated and high-volume to access or\r\nquery the Whois database except as reasonably necessary to register\r\ndomain names or modify existing registrations. VeriSign reserves the right\r\nto restrict your access to the Whois database in its sole discretion to ensure\r\noperational stability.  VeriSign may restrict or terminate your access to the\r\nWhois database for failure to abide by these terms of use. VeriSign\r\nreserves the right to modify these terms at any time.\r\n\r\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\r\nRegistrars.\r\n",
}


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_unregistered], indirect=True)
async def test_cname_whois_unregistered(fs, mock_dispatch_whois, httpx_mock):
    mock_data = {"bad.dns": {"CNAME": ["worse.dns."]}, "worse.dns": {"A": ["127.0.0.2"]}}

    mock_resolver = MockResolver(mock_data)
    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)
    findings = None
    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()

    assert findings
    assert {
        "target": "bad.dns",
        "cnames": ["worse.dns"],
        "signature_name": None,
        "matching_domain": None,
        "technique": "CNAME unregistered",
    } in findings
