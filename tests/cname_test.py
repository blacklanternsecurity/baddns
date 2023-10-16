import pytest
import requests
import datetime
from mock import patch
from baddns.modules.cname import BadDNS_cname
from .helpers import mock_signature_load

import ssl

# Disable SSL certificate verification
ssl._create_default_https_context = ssl._create_unverified_context

import functools

requests.adapters.BaseAdapter.send = functools.partialmethod(requests.adapters.BaseAdapter.send, verify=False)
requests.adapters.HTTPAdapter.send = functools.partialmethod(requests.adapters.HTTPAdapter.send, verify=False)
requests.Session.request = functools.partialmethod(requests.Session.request, verify=False)
requests.request = functools.partial(requests.request, verify=False)


@pytest.mark.asyncio
async def test_cname_dnsnxdomain_azure_match(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data)

    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)

    findings = None
    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)",
        "confidence": "PROBABLE",
        "signature": "Microsoft Azure Takeover Detection",
        "indicator": "azurewebsites.net",
        "trigger": "baddns.azurewebsites.net",
        "module": "CNAME",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_cname_dnsnxdomain_generic(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {"CNAME": ["baddns.somerandomthing.net."]}, "_NXDOMAIN": ["baddns.somerandomthing.net"]}
    mock_resolver = configure_mock_resolver(mock_data)

    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)

    findings = None
    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling CNAME, possible subdomain takeover (NXDOMAIN technique)",
        "confidence": "POSSIBLE",
        "signature": "GENERIC",
        "indicator": "Generic Dangling CNAME",
        "trigger": "baddns.somerandomthing.net",
        "module": "CNAME",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_cname_dnsnxdomain_azure_negative(fs, mock_dispatch_whois, configure_mock_resolver):
    mock_data = {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "baddns.azurewebsites.net.": {"A": "127.0.0.1"}}
    mock_resolver = configure_mock_resolver(mock_data)

    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)

    findings = None
    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()

    assert not findings


@pytest.mark.asyncio
async def test_cname_http_bigcartel_match(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    mock_data = {"bad.dns": {"CNAME": ["baddns.bigcartel.com"]}, "baddns.bigcartel.com": {"A": "127.0.0.1"}}
    mock_resolver = configure_mock_resolver(mock_data)

    httpx_mock.add_response(
        url="http://bad.dns/",
        status_code=200,
        text="<h1>Oops! We couldn&#8217;t find that page.</h1>",
    )

    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_bigcartel-takeover.yml")

    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)
    findings = None

    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling CNAME, probable subdomain takeover (HTTP String Match)",
        "confidence": "PROBABLE",
        "signature": "Bigcartel Takeover Detection",
        "indicator": "[Words: <h1>Oops! We couldn&#8217;t find that page.</h1> | Condition: and | Part: body] Matchers-Condition: and",
        "trigger": "baddns.bigcartel.com",
        "module": "CNAME",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_cname_http_bigcartel_negative(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    mock_data = {"bad.dns": {"CNAME": ["baddns.bigcartel.com"]}, "_NXDOMAIN": ["baddns.bigcartel.com"]}
    mock_resolver = configure_mock_resolver(mock_data)

    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_bigcartel-takeover.yml")

    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)
    findings = None
    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()
    assert findings
    expected = {
        "target": "bad.dns",
        "description": "Dangling CNAME, possible subdomain takeover (NXDOMAIN technique)",
        "confidence": "POSSIBLE",
        "signature": "GENERIC",
        "indicator": "Generic Dangling CNAME",
        "trigger": "baddns.bigcartel.com",
        "module": "CNAME",
    }
    assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
async def test_cname_chainedcname_nxdomain(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    mock_data = {
        "chain.bad.dns": {"CNAME": ["chain2.bad.dns."]},
        "chain2.bad.dns": {"CNAME": ["baddns.azurewebsites.net."]},
        "_NXDOMAIN": ["baddns.azurewebsites.net"],
    }
    mock_resolver = configure_mock_resolver(mock_data)

    target = "chain.bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)

    findings = None
    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()

    assert findings
    expected = {
        "target": "chain.bad.dns",
        "description": "Dangling CNAME, probable subdomain takeover (NXDOMAIN technique)",
        "confidence": "PROBABLE",
        "signature": "Microsoft Azure Takeover Detection",
        "indicator": "azurewebsites.net",
        "trigger": "chain2.bad.dns, baddns.azurewebsites.net",
        "module": "CNAME",
    }
    assert any(expected == finding.to_dict() for finding in findings)


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
async def test_cname_whois_expired(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    mock_data = {
        "bad.dns": {"CNAME": ["worse.dns."]},
        "_NXDOMAIN": ["worse.dns"],
    }
    mock_resolver = configure_mock_resolver(mock_data)
    target = "bad.dns"

    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)
    findings = None
    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "CNAME With Expired Registration (Expiration: [2023-02-25 15:56:10])",
        "confidence": "CONFIRMED",
        "signature": "N/A",
        "indicator": "Whois Data",
        "trigger": "worse.dns",
        "module": "CNAME",
    }
    assert any(expected == finding.to_dict() for finding in findings)


mock_whois_unregistered = {
    "type": "error",
    "data": "No match for \"WORSE.DNS\".\r\n>>> Last update of whois database: 2023-08-17T14:07:31Z <<<\r\n\r\nNOTICE: The expiration date displayed in this record is the date the\r\nregistrar's sponsorship of the domain name registration in the registry is\r\ncurrently set to expire. This date does not necessarily reflect the expiration\r\ndate of the domain name registrant's agreement with the sponsoring\r\nregistrar.  Users may consult the sponsoring registrar's Whois database to\r\nview the registrar's reported date of expiration for this registration.\r\n\r\nTERMS OF USE: You are not authorized to access or query our Whois\r\ndatabase through the use of electronic processes that are high-volume and\r\nautomated except as reasonably necessary to register domain names or\r\nmodify existing registrations; the Data in VeriSign Global Registry\r\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\r\ninformation purposes only, and to assist persons in obtaining information\r\nabout or related to a domain name registration record. VeriSign does not\r\nguarantee its accuracy. By submitting a Whois query, you agree to abide\r\nby the following terms of use: You agree that you may use this Data only\r\nfor lawful purposes and that under no circumstances will you use this Data\r\nto: (1) allow, enable, or otherwise support the transmission of mass\r\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\r\nor facsimile; or (2) enable high volume, automated, electronic processes\r\nthat apply to VeriSign (or its computer systems). The compilation,\r\nrepackaging, dissemination or other use of this Data is expressly\r\nprohibited without the prior written consent of VeriSign. You agree not to\r\nuse electronic processes that are automated and high-volume to access or\r\nquery the Whois database except as reasonably necessary to register\r\ndomain names or modify existing registrations. VeriSign reserves the right\r\nto restrict your access to the Whois database in its sole discretion to ensure\r\noperational stability.  VeriSign may restrict or terminate your access to the\r\nWhois database for failure to abide by these terms of use. VeriSign\r\nreserves the right to modify these terms at any time.\r\n\r\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\r\nRegistrars.\r\n",
}


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_unregistered], indirect=True)
async def test_cname_whois_unregistered_match(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    mock_data = {"bad.dns": {"CNAME": ["worse.dns."]}, "worse.dns": {"A": ["127.0.0.2"]}}
    mock_resolver = configure_mock_resolver(mock_data)

    target = "bad.dns"
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)
    findings = None
    if await baddns_cname.dispatch():
        findings = baddns_cname.analyze()

    assert findings
    expected = {
        "target": "bad.dns",
        "description": "CNAME unregistered",
        "confidence": "CONFIRMED",
        "signature": "N/A",
        "indicator": "Whois Data",
        "trigger": "worse.dns",
        "module": "CNAME",
    }
    assert any(expected == finding.to_dict() for finding in findings)


whois_mock_expired_baddata = {
    "type": "response",
    "data": {
        "domain_name": ["WORSE.DNS", "worse.dns"],
        "registrar": "Google LLC",
        "whois_server": "whois.google.com",
        "referral_url": None,
        "updated_date": datetime.datetime(2022, 4, 26, 17, 5, 40),
        "creation_date": datetime.datetime(2020, 4, 25, 15, 56, 10),
        "expiration_date": "2024-Jul-06",
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
@pytest.mark.parametrize("mock_dispatch_whois", [whois_mock_expired_baddata], indirect=True)
async def test_cname_whois_unregistered_baddata(fs, mock_dispatch_whois, httpx_mock, configure_mock_resolver):
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"CNAME": ["worse.dns."]}, "worse.dns": {"A": ["127.0.0.2"]}}
        mock_resolver = configure_mock_resolver(mock_data)

        target = "bad.dns"
        mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
        baddns_cname = BadDNS_cname(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)
        findings = None
        if await baddns_cname.dispatch():
            findings = baddns_cname.analyze()
            print(findings)
        assert not exit_mock.called
