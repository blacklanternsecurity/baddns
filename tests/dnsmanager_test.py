import pytest
from unittest.mock import AsyncMock
from baddns.lib.dnsmanager import DNSManager
from blastdns import MockClient


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

    def test_clean_string_no_dot(self):
        assert DNSManager._clean_dns_record("example.com") == "example.com"


class TestProcessAnswer:
    def setup_method(self):
        mock_client = MockClient()
        self.mgr = DNSManager("test.example.com", dns_client=mock_client)

    def test_none_answer(self):
        assert self.mgr.process_answer(None, "A") == []

    @pytest.mark.asyncio
    async def test_a_record(self):
        mock_client = MockClient()
        mock_client.mock_dns({"test.example.com": {"A": ["1.2.3.4"]}})
        result = await mock_client.resolve_full("test.example.com", "A")
        processed = self.mgr.process_answer(result, "A")
        assert "1.2.3.4" in processed

    @pytest.mark.asyncio
    async def test_mx_record(self):
        mock_client = MockClient()
        mock_client.mock_dns({"test.example.com": {"MX": ["10 mail.example.com."]}})
        result = await mock_client.resolve_full("test.example.com", "MX")
        processed = self.mgr.process_answer(result, "MX")
        assert "mail.example.com" in processed

    @pytest.mark.asyncio
    async def test_txt_record(self):
        mock_client = MockClient()
        mock_client.mock_dns({"test.example.com": {"TXT": ["v=spf1 include:example.com ~all"]}})
        result = await mock_client.resolve_full("test.example.com", "TXT")
        processed = self.mgr.process_answer(result, "TXT")
        assert "v=spf1 include:example.com ~all" in processed

    @pytest.mark.asyncio
    async def test_cname_record(self):
        mock_client = MockClient()
        mock_client.mock_dns({"test.example.com": {"CNAME": ["target.example.com."]}})
        result = await mock_client.resolve_full("test.example.com", "CNAME")
        processed = self.mgr.process_answer(result, "CNAME")
        assert "target.example.com" in processed

    @pytest.mark.asyncio
    async def test_ns_record(self):
        mock_client = MockClient()
        mock_client.mock_dns({"test.example.com": {"NS": ["ns1.example.com."]}})
        result = await mock_client.resolve_full("test.example.com", "NS")
        processed = self.mgr.process_answer(result, "NS")
        assert "ns1.example.com" in processed


class TestDoResolve:
    def setup_method(self):
        self.mock_client = MockClient()

    @pytest.mark.asyncio
    async def test_nxdomain(self):
        self.mock_client.mock_dns({"_NXDOMAIN": ["test.example.com"]})
        mgr = DNSManager("test.example.com", dns_client=self.mock_client)
        result = await mgr.do_resolve("test.example.com", "A")
        assert result is None
        assert mgr.answers["NXDOMAIN"] is True

    @pytest.mark.asyncio
    async def test_noanswer(self):
        # Host exists with A record but we query AAAA - no answer
        self.mock_client.mock_dns({"test.example.com": {"A": ["1.2.3.4"]}})
        mgr = DNSManager("test.example.com", dns_client=self.mock_client)
        result = await mgr.do_resolve("test.example.com", "AAAA")
        assert result is None
        assert mgr.answers["NoAnswer"] is True

    @pytest.mark.asyncio
    async def test_resolver_error(self):
        # Use AsyncMock to simulate a ResolverError from resolve_full
        from blastdns import ResolverError

        mock_client = AsyncMock()
        mock_client.resolve_full.side_effect = ResolverError("resolver timeout")
        mgr = DNSManager("test.example.com", dns_client=mock_client)
        result = await mgr.do_resolve("test.example.com", "A")
        assert result is None
        assert mgr.answers["NoAnswer"] is True

    @pytest.mark.asyncio
    async def test_blastdns_error(self):
        # Use AsyncMock to simulate a BlastDNSError from resolve_full
        from blastdns import BlastDNSError

        mock_client = AsyncMock()
        mock_client.resolve_full.side_effect = BlastDNSError("something broke")
        mgr = DNSManager("test.example.com", dns_client=mock_client)
        result = await mgr.do_resolve("test.example.com", "A")
        assert result is None

    @pytest.mark.asyncio
    async def test_a_record_sets_ips(self):
        self.mock_client.mock_dns({"test.example.com": {"A": ["1.2.3.4"]}})
        mgr = DNSManager("test.example.com", dns_client=self.mock_client)
        result = await mgr.do_resolve("test.example.com", "A")
        assert "1.2.3.4" in result
        assert "1.2.3.4" in mgr.ips

    @pytest.mark.asyncio
    async def test_aaaa_record_sets_ips(self):
        self.mock_client.mock_dns({"test.example.com": {"AAAA": ["::1"]}})
        mgr = DNSManager("test.example.com", dns_client=self.mock_client)
        result = await mgr.do_resolve("test.example.com", "AAAA")
        assert "::1" in result
        assert "::1" in mgr.ips

    @pytest.mark.asyncio
    async def test_cname_chain(self):
        self.mock_client.mock_dns(
            {
                "test.example.com": {"CNAME": ["step1.example.com."]},
                "step1.example.com": {"CNAME": ["step2.example.com."]},
            }
        )
        mgr = DNSManager("test.example.com", dns_client=self.mock_client)
        result = await mgr.do_resolve("test.example.com", "CNAME")
        assert result == ["step1.example.com", "step2.example.com"]

    @pytest.mark.asyncio
    async def test_cname_chain_nxdomain(self):
        self.mock_client.mock_dns(
            {
                "test.example.com": {"CNAME": ["step1.example.com."]},
                "_NXDOMAIN": ["step1.example.com"],
            }
        )
        mgr = DNSManager("test.example.com", dns_client=self.mock_client)
        result = await mgr.do_resolve("test.example.com", "CNAME")
        assert result == ["step1.example.com"]

    @pytest.mark.asyncio
    async def test_empty_result(self):
        # Host has no records at all
        self.mock_client.mock_dns({})
        mgr = DNSManager("test.example.com", dns_client=self.mock_client)
        result = await mgr.do_resolve("test.example.com", "NS")
        assert result is None


class TestDispatchDNS:
    @pytest.mark.asyncio
    async def test_omit_types(self):
        from blastdns import ResolverError

        mock_client = AsyncMock()
        mock_client.resolvers = ["127.0.0.1:53"]
        mock_client.resolve_multi_full.side_effect = ResolverError("no data")
        mgr = DNSManager("test.example.com", dns_client=mock_client)
        await mgr.dispatchDNS(omit_types=["A", "AAAA", "MX", "CNAME", "NS", "SOA", "TXT"])
        # Only NSEC should have been queried
        mock_client.resolve_multi_full.assert_called_once()
        call_args = mock_client.resolve_multi_full.call_args
        assert call_args[0][1] == ["NSEC"]

    @pytest.mark.asyncio
    async def test_timeout_in_dispatch(self):
        from blastdns import ResolverError

        mock_client = AsyncMock()
        mock_client.resolvers = ["127.0.0.1:53"]
        mock_client.resolve_multi_full.side_effect = ResolverError("DNS timeout")
        mgr = DNSManager("test.example.com", dns_client=mock_client)
        await mgr.dispatchDNS()
        # dispatchDNS catches ResolverError and sets NoAnswer, all type answers stay None
        assert mgr.answers["NoAnswer"] is True
        for rtype in DNSManager.dns_record_types:
            assert mgr.answers[rtype] is None


class TestDNSManagerInit:
    def test_default_resolver(self):
        mgr = DNSManager("test.com")
        assert mgr.target == "test.com"
        assert mgr.dns_client is not None

    def test_custom_nameservers(self):
        mgr = DNSManager("test.com", custom_nameservers=["1.1.1.1"])
        # When custom nameservers are provided, a new client is created with those resolvers
        assert "1.1.1.1" in str(mgr.dns_client.resolvers)

    def test_reset_answers(self):
        mock_client = MockClient()
        mgr = DNSManager("test.com", dns_client=mock_client)
        mgr.answers["A"] = ["1.2.3.4"]
        mgr.reset_answers()
        assert mgr.answers["A"] is None
        assert mgr.answers["NXDOMAIN"] is False
