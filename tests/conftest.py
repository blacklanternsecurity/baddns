import pytest
from baddns.lib.dnsmanager import DNSManager
from baddns.lib.whoismanager import WhoisManager
from baddns.lib.dnswalk import DnsWalk
from .helpers import MockResolver, mock_process_answer, DnsWalkHarness

import dns.asyncquery


@pytest.fixture()
def mock_dispatch_whois(request, monkeypatch):
    value = getattr(request, "param", None)

    async def fake_dispatch_whois(self):
        print(f"Running mock_dispatch_whois with value: [{value}]")
        self.whois_result = value

    monkeypatch.setattr(WhoisManager, "dispatchWHOIS", fake_dispatch_whois)


@pytest.fixture()
def configure_mock_resolver(monkeypatch):
    def mock_ns_trace_method_generator(return_list):
        async def mock_ns_trace(self, target):
            return return_list

        return mock_ns_trace

    def _configure(mock_data, mock_dnswalk_data=[]):
        mock_resolver = MockResolver(mock_data)
        monkeypatch.setattr(DNSManager, "process_answer", mock_process_answer)

        # Mock DNSWalk
        monkeypatch.setattr(DnsWalk, "ns_trace", mock_ns_trace_method_generator(mock_dnswalk_data))
        return mock_resolver

    return _configure


@pytest.fixture()
def dnswalk_harness(request, monkeypatch):
    mock_data = getattr(request, "param", {})

    def init_wrapper(mock_data):
        def mock_init(self):
            pass

        return mock_init

    monkeypatch.setattr(DnsWalkHarness, "mock_data", mock_data)
    monkeypatch.setattr(DnsWalk, "__init__", init_wrapper(mock_data))
    monkeypatch.setattr(DnsWalk, "a_resolve", DnsWalkHarness.mock_a_resolve)
    monkeypatch.setattr(DnsWalk, "root_servers", ["127.0.0.1"])
    monkeypatch.setattr(dns.asyncquery, "udp_with_fallback", DnsWalkHarness.mock_udp_with_fallback)
