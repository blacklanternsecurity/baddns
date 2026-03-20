import pytest
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset
import dns.flags
import dns.exception
from unittest.mock import AsyncMock, MagicMock, patch
from baddns.lib.dnswalk import DnsWalk


class TestAResolve:
    @pytest.mark.asyncio
    async def test_a_resolve_success(self):
        mock_dns_manager = MagicMock()
        mock_dns_manager.do_resolve = AsyncMock(return_value=["1.2.3.4", "5.6.7.8"])
        dw = DnsWalk(mock_dns_manager)
        result = await dw.a_resolve("ns.example.com")
        assert "1.2.3.4" in result
        assert "5.6.7.8" in result

    @pytest.mark.asyncio
    async def test_a_resolve_none(self):
        mock_dns_manager = MagicMock()
        mock_dns_manager.do_resolve = AsyncMock(return_value=None)
        dw = DnsWalk(mock_dns_manager)
        result = await dw.a_resolve("ns.example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_a_resolve_empty(self):
        mock_dns_manager = MagicMock()
        mock_dns_manager.do_resolve = AsyncMock(return_value=[])
        dw = DnsWalk(mock_dns_manager)
        result = await dw.a_resolve("ns.example.com")
        assert result is None


class TestRawQueryWithRetry:
    @pytest.mark.asyncio
    async def test_success(self):
        mock_dns_manager = MagicMock()
        dw = DnsWalk(mock_dns_manager, raw_query_max_retries=2, raw_query_retry_wait=0)
        mock_response = MagicMock()
        with patch("dns.asyncquery.udp_with_fallback", new_callable=AsyncMock) as mock_udp:
            mock_udp.return_value = (mock_response, False)
            response, tcp = await dw.raw_query_with_retry(MagicMock(), "1.2.3.4")
            assert response == mock_response
            assert tcp is False

    @pytest.mark.asyncio
    async def test_timeout_retry(self):
        mock_dns_manager = MagicMock()
        dw = DnsWalk(mock_dns_manager, raw_query_max_retries=2, raw_query_retry_wait=0)
        with patch("dns.asyncquery.udp_with_fallback", new_callable=AsyncMock) as mock_udp:
            mock_udp.side_effect = dns.exception.Timeout
            response, tcp = await dw.raw_query_with_retry(MagicMock(), "1.2.3.4")
            assert response is None
            assert tcp is None
            assert mock_udp.call_count == 2

    @pytest.mark.asyncio
    async def test_unexpected_error(self):
        mock_dns_manager = MagicMock()
        dw = DnsWalk(mock_dns_manager, raw_query_max_retries=2, raw_query_retry_wait=0)
        with patch("dns.asyncquery.udp_with_fallback", new_callable=AsyncMock) as mock_udp:
            mock_udp.side_effect = RuntimeError("unexpected")
            response, tcp = await dw.raw_query_with_retry(MagicMock(), "1.2.3.4")
            assert response is None
            assert tcp is None

    @pytest.mark.asyncio
    async def test_truncated_retry(self):
        mock_dns_manager = MagicMock()
        dw = DnsWalk(mock_dns_manager, raw_query_max_retries=2, raw_query_retry_wait=0)
        with patch("dns.asyncquery.udp_with_fallback", new_callable=AsyncMock) as mock_udp:
            mock_udp.side_effect = dns.message.Truncated
            response, tcp = await dw.raw_query_with_retry(MagicMock(), "1.2.3.4")
            assert response is None


class TestNsRecursiveSolve:
    @pytest.mark.asyncio
    async def test_max_depth(self):
        mock_dns_manager = MagicMock()
        dw = DnsWalk(mock_dns_manager)
        result = await dw.ns_recursive_solve(["1.2.3.4"], "example.com", depth=11)
        assert result == []

    @pytest.mark.asyncio
    async def test_no_response(self):
        mock_dns_manager = MagicMock()
        dw = DnsWalk(mock_dns_manager, raw_query_max_retries=1, raw_query_retry_wait=0)
        with patch("dns.asyncquery.udp_with_fallback", new_callable=AsyncMock) as mock_udp:
            mock_udp.return_value = (None, None)
            result = await dw.ns_recursive_solve(["1.2.3.4"], "example.com", depth=0)
            assert result == []

    @pytest.mark.asyncio
    async def test_soa_in_authority(self):
        mock_dns_manager = MagicMock()
        dw = DnsWalk(mock_dns_manager, raw_query_max_retries=1, raw_query_retry_wait=0)

        # Build a response with SOA in authority
        response = dns.message.Message()
        response.flags |= dns.flags.AA | dns.flags.QR
        soa_data = "ns1.example.com. admin.example.com. 2021081901 3600 1800 604800 3600"
        rrset = dns.rrset.from_text("example.com", 3600, dns.rdataclass.IN, dns.rdatatype.SOA, soa_data)
        response.authority.append(rrset)

        with patch("dns.asyncquery.udp_with_fallback", new_callable=AsyncMock) as mock_udp:
            mock_udp.return_value = (response, False)
            result = await dw.ns_recursive_solve(["1.2.3.4"], "example.com", depth=0)
            assert result is None

    @pytest.mark.asyncio
    async def test_same_nameservers_loop_prevention(self):
        mock_dns_manager = MagicMock()
        mock_dns_manager.do_resolve = AsyncMock(return_value=["1.2.3.4"])
        dw = DnsWalk(mock_dns_manager, raw_query_max_retries=1, raw_query_retry_wait=0)

        # Build response with NS authority pointing back to same IP
        response = dns.message.Message()
        response.flags |= dns.flags.AA | dns.flags.QR
        rrset = dns.rrset.from_text("example.com", 3600, dns.rdataclass.IN, dns.rdatatype.NS, "ns1.example.com.")
        response.authority.append(rrset)

        with patch("dns.asyncquery.udp_with_fallback", new_callable=AsyncMock) as mock_udp:
            mock_udp.return_value = (response, False)
            result = await dw.ns_recursive_solve(["1.2.3.4"], "example.com", depth=0)
            assert result == []

    @pytest.mark.asyncio
    async def test_answer_section_with_ns(self):
        mock_dns_manager = MagicMock()
        dw = DnsWalk(mock_dns_manager, raw_query_max_retries=1, raw_query_retry_wait=0)

        # Build response with NS in answer section (no authority)
        response = dns.message.Message()
        response.flags |= dns.flags.AA | dns.flags.QR
        rrset = dns.rrset.from_text("example.com", 3600, dns.rdataclass.IN, dns.rdatatype.NS, "ns1.found.com.")
        response.answer.append(rrset)

        with patch("dns.asyncquery.udp_with_fallback", new_callable=AsyncMock) as mock_udp:
            mock_udp.return_value = (response, False)
            result = await dw.ns_recursive_solve(["1.2.3.4"], "example.com", depth=0)
            assert "ns1.found.com" in result

    @pytest.mark.asyncio
    async def test_answer_section_with_cname(self):
        mock_dns_manager = MagicMock()
        mock_dns_manager.do_resolve = AsyncMock(return_value=["ns1.resolved.com"])
        dw = DnsWalk(mock_dns_manager, raw_query_max_retries=1, raw_query_retry_wait=0)

        # Build response with CNAME in answer section
        response = dns.message.Message()
        response.flags |= dns.flags.AA | dns.flags.QR
        rrset = dns.rrset.from_text("example.com", 3600, dns.rdataclass.IN, dns.rdatatype.CNAME, "alias.example.com.")
        response.answer.append(rrset)

        with patch("dns.asyncquery.udp_with_fallback", new_callable=AsyncMock) as mock_udp:
            mock_udp.return_value = (response, False)
            result = await dw.ns_recursive_solve(["1.2.3.4"], "example.com", depth=0)
            assert "ns1.resolved.com" in result

    @pytest.mark.asyncio
    async def test_no_authority_no_answer(self):
        mock_dns_manager = MagicMock()
        dw = DnsWalk(mock_dns_manager, raw_query_max_retries=1, raw_query_retry_wait=0)

        # Build empty response (no authority, no answer)
        response = dns.message.Message()
        response.flags |= dns.flags.AA | dns.flags.QR

        with patch("dns.asyncquery.udp_with_fallback", new_callable=AsyncMock) as mock_udp:
            mock_udp.return_value = (response, False)
            result = await dw.ns_recursive_solve(["1.2.3.4"], "example.com", depth=0)
            assert result == []


class TestNsTrace:
    @pytest.mark.asyncio
    async def test_ns_trace_none_result(self):
        mock_dns_manager = MagicMock()
        dw = DnsWalk(mock_dns_manager, raw_query_max_retries=1, raw_query_retry_wait=0)

        async def mock_recursive_solve(*args, **kwargs):
            return None

        dw.ns_recursive_solve = mock_recursive_solve
        result = await dw.ns_trace("example.com")
        assert result == []
