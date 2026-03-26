import os
import dns
from importlib import resources

from blastdns import MockClient


def mock_process_answer(self, result, rdatatype):
    """Test helper that extracts answers from a DNSResult, returning plain strings.

    This is used by conftest to monkeypatch DNSManager.process_answer so that
    test assertions can work with simple string data.
    """
    if result is None:
        return []
    results = []
    for record in result.response.answers:
        for rdtype, value in record.rdata.items():
            value = str(value).rstrip(".").lower()
            results.append(value)
    return results


class MockDNSWalk:
    def __init__(self, mock_dnswalk_data=[]):
        self.mock_dnswalk_data = mock_dnswalk_data

    async def ns_trace(self, target):
        self.mock_dnswalk_data


def create_mock_client(mock_data):
    """Create a blastdns MockClient configured with the given mock data."""
    client = MockClient()
    client.mock_dns(mock_data)
    return client


def mock_signature_load(fs, signature_filename):
    fake_dir = "/tmp/signatures"
    if not os.path.exists(fake_dir):
        fs.create_dir(fake_dir)
    signatures_dir = resources.files("baddns") / "signatures"
    signature_file = os.path.join(signatures_dir, signature_filename)
    fs.add_real_file(signature_file)
    os.symlink(signature_file, os.path.join(fake_dir, signature_filename))


class MockWhois:
    pass


class MockQueryAnswer:
    def __init__(self, authority=[], answer=[]):
        self.authority = authority
        self.answer = answer

    def find_rrset(self, section, qname, rdclass, rdtype):
        for rrset in section:
            if rrset.name == qname and rrset.rdclass == rdclass and rrset.rdtype == rdtype:
                return rrset
        raise KeyError("No matching RRset found.")

    class MockRRset:
        def __init__(self, name, rdclass, rdtype, target):
            self.name = name
            self.rdclass = rdclass
            self.rdtype = rdtype
            self.target = target
            self.ttl = 3600  # default TTL for simplicity

        def __iter__(self):
            yield self


class DnsWalkHarness:
    mock_data = {}

    @staticmethod
    def reverse_lookup(ip_address):
        if DnsWalkHarness.mock_data["a_records"]:
            for hostname, ip in DnsWalkHarness.mock_data["a_records"].items():
                if ip == ip_address:
                    return hostname
            return ip_address  # If no hostname found, return the original IP.

    async def mock_udp_with_fallback(query_msg, nameserver_ip, timeout=5.0):
        domain = query_msg.question[0].name.to_text().rstrip(".")
        record_type = dns.rdatatype.to_text(query_msg.question[0].rdtype)

        mock_response = DnsWalkHarness.generate_mock_response(domain, record_type, nameserver_ip)
        return mock_response, False

    async def mock_a_resolve(dummy, domain, glue=None):
        if glue:
            glue_ips = glue.get(domain.lower())
            if glue_ips:
                return glue_ips
        if domain in DnsWalkHarness.mock_data["a_records"]:
            return [DnsWalkHarness.mock_data["a_records"][domain]]  # Return as a list to match the expected structure
        return []  # Return empty list if domain not found in mock data

    @staticmethod
    def generate_mock_response(domain, record_type, nameserver_ip):
        # Creating a base response message
        response = dns.message.Message()

        # Setting up basic flags. These may need to be adjusted.
        response.flags |= dns.flags.AA  # Mark it as authoritative
        response.flags |= dns.flags.QR  # This is a response

        # Attempt to find records using both the IP and its associated hostname, if any
        potential_keys = {nameserver_ip}
        hostname = DnsWalkHarness.reverse_lookup(nameserver_ip)
        if hostname and hostname != nameserver_ip:
            potential_keys.add(hostname)

        for key in potential_keys:
            for entry in DnsWalkHarness.mock_data["ns_records"]:
                if key in entry:
                    for ans in entry[key].get("answer", []):
                        rrset = dns.rrset.from_text(domain, 3600, dns.rdataclass.IN, dns.rdatatype.NS, ans)
                        response.answer.append(rrset)
                    for auth in entry[key].get("authority", []):
                        rrset = dns.rrset.from_text(domain, 3600, dns.rdataclass.IN, dns.rdatatype.NS, auth)
                        response.authority.append(rrset)

        if "soa_records" in DnsWalkHarness.mock_data:
            for key in potential_keys:
                for entry in DnsWalkHarness.mock_data["soa_records"]:
                    if key in entry:
                        for auth in entry[key].get("authority", []):
                            soa_filler_data = "ns1.example.com. admin.example.com. 2021081901 3600 1800 604800 3600"
                            rrset = dns.rrset.from_text(
                                domain, 3600, dns.rdataclass.IN, dns.rdatatype.SOA, soa_filler_data
                            )
                            response.authority.append(rrset)
        return response
