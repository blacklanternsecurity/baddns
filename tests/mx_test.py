import pytest
import datetime
from mock import patch
from .helpers import mock_signature_load
from baddns.modules.mx import BadDNS_mx


mock_whois_unregistered = {
    "type": "error",
    "data": "No match for \"WORSE.DNS\".\r\n>>> Last update of whois database: 2023-08-17T14:07:31Z <<<\r\n\r\nNOTICE: The expiration date displayed in this record is the date the\r\nregistrar's sponsorship of the domain name registration in the registry is\r\ncurrently set to expire. This date does not necessarily reflect the expiration\r\ndate of the domain name registrant's agreement with the sponsoring\r\nregistrar.  Users may consult the sponsoring registrar's Whois database to\r\nview the registrar's reported date of expiration for this registration.\r\n\r\nTERMS OF USE: You are not authorized to access or query our Whois\r\ndatabase through the use of electronic processes that are high-volume and\r\nautomated except as reasonably necessary to register domain names or\r\nmodify existing registrations; the Data in VeriSign Global Registry\r\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\r\ninformation purposes only, and to assist persons in obtaining information\r\nabout or related to a domain name registration record. VeriSign does not\r\nguarantee its accuracy. By submitting a Whois query, you agree to abide\r\nby the following terms of use: You agree that you may use this Data only\r\nfor lawful purposes and that under no circumstances will you use this Data\r\nto: (1) allow, enable, or otherwise support the transmission of mass\r\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\r\nor facsimile; or (2) enable high volume, automated, electronic processes\r\nthat apply to VeriSign (or its computer systems). The compilation,\r\nrepackaging, dissemination or other use of this Data is expressly\r\nprohibited without the prior written consent of VeriSign. You agree not to\r\nuse electronic processes that are automated and high-volume to access or\r\nquery the Whois database except as reasonably necessary to register\r\ndomain names or modify existing registrations. VeriSign reserves the right\r\nto restrict your access to the Whois database in its sole discretion to ensure\r\noperational stability.  VeriSign may restrict or terminate your access to the\r\nWhois database for failure to abide by these terms of use. VeriSign\r\nreserves the right to modify these terms at any time.\r\n\r\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\r\nRegistrars.\r\n",
}

mock_whois_expired = {
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
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_unregistered], indirect=True)
async def test_mx_unregistered(fs, mock_dispatch_whois, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"MX": ["mail2.worse.dns", "mail2.worse.dns"]}}
        mock_resolver = configure_mock_resolver(mock_data)
        mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

        target = "bad.dns"
        baddns_mx = BadDNS_mx(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)
        findings = None
        if await baddns_mx.dispatch():
            findings = baddns_mx.analyze()
        assert not exit_mock.called

        expected = {
            "target": "bad.dns",
            "description": "MX unregistered",
            "confidence": "CONFIRMED",
            "signature": "N/A",
            "indicator": "Whois Data",
            "trigger": "mail2.worse.dns",
            "module": "MX",
        }
        assert any(expected == finding.to_dict() for finding in findings)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_dispatch_whois", [mock_whois_expired], indirect=True)
async def test_mx_expired(fs, mock_dispatch_whois, configure_mock_resolver, cached_suffix_list):
    with patch("sys.exit") as exit_mock:
        mock_data = {"bad.dns": {"MX": ["mail2.worse.dns", "mail2.worse.dns"]}}
        mock_resolver = configure_mock_resolver(mock_data)
        mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

        target = "bad.dns"
        baddns_mx = BadDNS_mx(target, signatures_dir="/tmp/signatures", dns_client=mock_resolver)
        findings = None
        if await baddns_mx.dispatch():
            findings = baddns_mx.analyze()
        assert not exit_mock.called

        expected = {
            "target": "bad.dns",
            "description": "MX Registration Expired (Expiration: [2023-02-25 15:56:10]",
            "confidence": "CONFIRMED",
            "signature": "N/A",
            "indicator": "Whois Data",
            "trigger": "mail2.worse.dns",
            "module": "MX",
        }
        assert any(expected == finding.to_dict() for finding in findings)
