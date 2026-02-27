import pytest
import dns.resolver
import dns.rdatatype
import dns.name
import dns.rdata
import dns.rrset
import dns.rdataclass
from unittest.mock import AsyncMock, MagicMock
from baddns.lib.dnsmanager import DNSManager


class TestGetIPv4:
    def test_get_ipv4(self):
        records = ["1.2.3.4", "5.6.7.8"]
        result = DNSManager.get_ipv4(records)
        assert result == ["1.2.3.4", "5.6.7.8"]

    def test_get_ipv4_empty(self):
        assert DNSManager.get_ipv4([]) == []


class TestGetIPv6:
    def test_get_ipv6(self):
        records = ["::1", "dead::beef"]
        result = DNSManager.get_ipv6(records)
        assert result == ["::1", "dead::beef"]

    def test_get_ipv6_empty(self):
        assert DNSManager.get_ipv6([]) == []


class TestCleanDnsRecord:
    def test_clean_string(self):
        assert DNSManager._clean_dns_record("example.com.") == "example.com"

    def test_clean_rdata_object(self):
        mock_rdata = MagicMock()
        mock_rdata.to_text.return_value = "example.com."
        assert DNSManager._clean_dns_record(mock_rdata) == "example.com"


class TestProcessAnswer:
    def setup_method(self):
        self.mgr = DNSManager("test.example.com", dns_client=MagicMock())

    def test_none_answer(self):
        assert self.mgr.process_answer(None, "A") == []

    def test_a_record(self):
        rr = MagicMock()
        rr.rdtype.name = "A"
        rr.to_text.return_value = "1.2.3.4"
        result = self.mgr.process_answer([rr], "A")
        assert "1.2.3.4" in result

    def test_soa_record(self):
        rr = MagicMock()
        rr.rdtype.name = "SOA"
        rr.mname.to_text.return_value = "ns1.example.com."
        result = self.mgr.process_answer([rr], "SOA")
        assert "ns1.example.com" in result

    def test_mx_record(self):
        rr = MagicMock()
        rr.rdtype.name = "MX"
        rr.exchange.to_text.return_value = "mail.example.com."
        result = self.mgr.process_answer([rr], "MX")
        assert "mail.example.com" in result

    def test_srv_record(self):
        rr = MagicMock()
        rr.rdtype.name = "SRV"
        rr.target.to_text.return_value = "sipdir.example.com."
        result = self.mgr.process_answer([rr], "SRV")
        assert "sipdir.example.com" in result

    def test_txt_record(self):
        rr = MagicMock()
        rr.rdtype.name = "TXT"
        rr.strings = [b"v=spf1 include:example.com ~all"]
        result = self.mgr.process_answer([rr], "TXT")
        assert "v=spf1 include:example.com ~all" in result

    def test_nsec_record(self):
        rr = MagicMock()
        rr.rdtype.name = "NSEC"
        rr.next.to_text.return_value = "next.example.com."
        result = self.mgr.process_answer([rr], "NSEC")
        assert "next.example.com" in result

    def test_unknown_record_type(self):
        rr = MagicMock()
        rr.rdtype.name = "CAA"
        result = self.mgr.process_answer([rr], "CAA")
        assert result == []


class TestDoResolve:
    def setup_method(self):
        self.mock_client = AsyncMock()
        self.mgr = DNSManager("test.example.com", dns_client=self.mock_client)

    @pytest.mark.asyncio
    async def test_noanswer(self):
        self.mock_client.resolve.side_effect = dns.resolver.NoAnswer
        result = await self.mgr.do_resolve("test.example.com", "A")
        assert result is None
        assert self.mgr.answers["NoAnswer"] is True

    @pytest.mark.asyncio
    async def test_nxdomain(self):
        self.mock_client.resolve.side_effect = dns.resolver.NXDOMAIN
        result = await self.mgr.do_resolve("test.example.com", "A")
        assert result is None
        assert self.mgr.answers["NXDOMAIN"] is True

    @pytest.mark.asyncio
    async def test_lifetime_timeout(self):
        self.mock_client.resolve.side_effect = dns.resolver.LifetimeTimeout(timeout=5.0, errors=[])
        result = await self.mgr.do_resolve("test.example.com", "A")
        assert result is None

    @pytest.mark.asyncio
    async def test_generic_exception(self):
        self.mock_client.resolve.side_effect = Exception("something broke")
        result = await self.mgr.do_resolve("test.example.com", "A")
        assert result is None

    @pytest.mark.asyncio
    async def test_a_record_sets_ips(self):
        mock_rr = MagicMock()
        mock_rr.rdtype.name = "A"
        mock_rr.to_text.return_value = "1.2.3.4"
        self.mock_client.resolve.return_value = [mock_rr]
        result = await self.mgr.do_resolve("test.example.com", "A")
        assert "1.2.3.4" in result
        assert "1.2.3.4" in self.mgr.ips

    @pytest.mark.asyncio
    async def test_aaaa_record_sets_ips(self):
        mock_rr = MagicMock()
        mock_rr.rdtype.name = "AAAA"
        mock_rr.to_text.return_value = "::1"
        self.mock_client.resolve.return_value = [mock_rr]
        result = await self.mgr.do_resolve("test.example.com", "AAAA")
        assert "::1" in result
        assert "::1" in self.mgr.ips

    @pytest.mark.asyncio
    async def test_cname_chain(self):
        mock_rr1 = MagicMock()
        mock_rr1.rdtype.name = "CNAME"
        mock_rr1.to_text.return_value = "step1.example.com."

        mock_rr2 = MagicMock()
        mock_rr2.rdtype.name = "CNAME"
        mock_rr2.to_text.return_value = "step2.example.com."

        self.mock_client.resolve.side_effect = [
            [mock_rr1],  # first resolve
            [mock_rr2],  # chain step 1
            [],  # chain ends
        ]
        result = await self.mgr.do_resolve("test.example.com", "CNAME")
        assert result == ["step1.example.com", "step2.example.com"]

    @pytest.mark.asyncio
    async def test_cname_chain_nxdomain(self):
        mock_rr1 = MagicMock()
        mock_rr1.rdtype.name = "CNAME"
        mock_rr1.to_text.return_value = "step1.example.com."

        self.mock_client.resolve.side_effect = [
            [mock_rr1],
            dns.resolver.NXDOMAIN,
        ]
        result = await self.mgr.do_resolve("test.example.com", "CNAME")
        assert result == ["step1.example.com"]

    @pytest.mark.asyncio
    async def test_empty_result(self):
        self.mock_client.resolve.return_value = []
        result = await self.mgr.do_resolve("test.example.com", "NS")
        assert result is None


class TestDispatchDNS:
    def setup_method(self):
        self.mock_client = AsyncMock()
        self.mgr = DNSManager("test.example.com", dns_client=self.mock_client)

    @pytest.mark.asyncio
    async def test_omit_types(self):
        self.mock_client.resolve.return_value = []
        await self.mgr.dispatchDNS(omit_types=["A", "AAAA", "MX", "CNAME", "NS", "SOA", "TXT"])
        # Only NSEC should have been queried
        assert self.mock_client.resolve.call_count == 1

    @pytest.mark.asyncio
    async def test_timeout_in_dispatch(self):
        self.mock_client.resolve.side_effect = dns.resolver.LifetimeTimeout(timeout=5.0, errors=[])
        await self.mgr.dispatchDNS()
        # do_resolve catches LifetimeTimeout and returns None, so all answers should be None
        for rtype in DNSManager.dns_record_types:
            assert self.mgr.answers[rtype] is None


class TestDNSManagerInit:
    def test_default_resolver(self):
        mgr = DNSManager("test.com")
        assert mgr.target == "test.com"
        assert mgr.dns_client is not None

    def test_custom_nameservers(self):
        mock_client = MagicMock()
        DNSManager("test.com", dns_client=mock_client, custom_nameservers=["1.1.1.1"])
        assert mock_client.nameservers == ["1.1.1.1"]

    def test_reset_answers(self):
        mock_client = MagicMock()
        mgr = DNSManager("test.com", dns_client=mock_client)
        mgr.answers["A"] = ["1.2.3.4"]
        mgr.reset_answers()
        assert mgr.answers["A"] is None
        assert mgr.answers["NXDOMAIN"] is False
