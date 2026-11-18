import os
import site
import pytest
from baddns.lib.whoismanager import WhoisManager
from baddns.lib.dnswalk import DnsWalk
from baddns.lib.dnsmanager import DNSManager
from baddns.mock_blasthttp import MockBlastHTTP
from .helpers import create_mock_client, DnsWalkHarness

import dns.asyncquery


@pytest.fixture
def mock_http():
    """A fresh MockBlastHTTP per test. Tests register responses with
    ``mock_http.add_response(url=..., status=, body=, headers=)`` and pass the
    fixture through to BadDNS_* constructors as ``http_client=mock_http``."""
    return MockBlastHTTP()


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
local_test_file = os.path.join(PROJECT_ROOT, "tests", "cached_suffix_list.dat")
with open(local_test_file, "r") as real_file:
    CACHED_SUFFIX_LIST_CONTENTS = real_file.read()


@pytest.fixture(autouse=True)
def no_rdap_bootstrap(monkeypatch):
    """Start every test with an empty RDAP server list, so WhoisManager goes straight to WHOIS and no test
    fetches IANA's bootstrap file or queries a real RDAP server. RDAP tests set ``_rdap_servers`` themselves."""
    monkeypatch.setattr(WhoisManager, "_rdap_servers", {})


@pytest.fixture()
def mock_dispatch_whois(request, monkeypatch):
    value = getattr(request, "param", None)
    WhoisManager.clear_cache()

    async def fake_dispatch_whois(self):
        print(f"Running mock_dispatch_whois with value: [{value}]")
        self.whois_result = value

    monkeypatch.setattr(WhoisManager, "dispatchWHOIS", fake_dispatch_whois)


@pytest.fixture
def cached_suffix_list(fs):
    site_packages_dir = site.getsitepackages()[0]
    expected_path = os.path.join(site_packages_dir, "whois", "data", "public_suffix_list.dat")
    fs.create_file(expected_path, contents=CACHED_SUFFIX_LIST_CONTENTS)
    yield


# When pyfakefs is active, tldextract's HTTPS fetch of the public suffix list
# tries to read certifi's cacert.pem and fails with OSError (path not in fake fs).
# That OSError is not caught by tldextract's snapshot fallback, which only catches
# requests.exceptions.RequestException. Exposing the real cacert.pem lets the
# fetch fail at the network layer instead, so the bundled snapshot is used.
@pytest.fixture(autouse=True)
def _expose_certifi_to_pyfakefs(request):
    if "fs" not in request.fixturenames:
        yield
        return
    fs = request.getfixturevalue("fs")
    try:
        import certifi

        fs.add_real_file(certifi.where(), read_only=True)
    except (ImportError, FileExistsError, OSError):
        pass
    yield


@pytest.fixture()
def configure_mock_resolver(monkeypatch):
    def mock_ns_trace_method_generator(return_list):
        async def mock_ns_trace(self, target):
            return return_list

        return mock_ns_trace

    def _configure(mock_data, mock_dnswalk_data=[]):
        # Extract NSEC data before passing to MockClient — hickory's zone-file
        # parser refuses to construct NSEC records ("should be dynamically generated"),
        # so we handle NSEC via monkeypatch on DNSManager instead.
        nsec_data = {}
        filtered_data = {}
        for host, records in mock_data.items():
            if isinstance(records, dict) and "NSEC" in records:
                nsec_data[host] = records["NSEC"]
                remaining = {k: v for k, v in records.items() if k != "NSEC"}
                if remaining:
                    filtered_data[host] = remaining
            else:
                filtered_data[host] = records

        mock_client = create_mock_client(filtered_data)

        if nsec_data:
            original_do_resolve = DNSManager.do_resolve
            original_dispatch = DNSManager.dispatchDNS

            async def patched_do_resolve(self, target, rdatatype):
                if rdatatype == "NSEC" and target in nsec_data:
                    return nsec_data[target]
                return await original_do_resolve(self, target, rdatatype)

            async def patched_dispatch(self, omit_types=[]):
                await original_dispatch(self, omit_types=omit_types)
                if "NSEC" not in omit_types and self.target in nsec_data:
                    self.answers["NSEC"] = nsec_data[self.target]

            monkeypatch.setattr(DNSManager, "do_resolve", patched_do_resolve)
            monkeypatch.setattr(DNSManager, "dispatchDNS", patched_dispatch)

        # Mock DNSWalk
        monkeypatch.setattr(DnsWalk, "ns_trace", mock_ns_trace_method_generator(mock_dnswalk_data))
        return mock_client

    return _configure


@pytest.fixture()
def dnswalk_harness(request, monkeypatch):
    mock_data = getattr(request, "param", {})

    def init_wrapper(mock_data):
        def mock_init(self, dns_manager, *args, **kwargs):  # dns_manager as positional, others as kwargs
            # Manually set the attributes that are normally initialized
            self.dns_manager = dns_manager
            self.raw_query_max_retries = kwargs.get("raw_query_max_retries", 6)
            self.raw_query_timeout = kwargs.get("raw_query_timeout", 6.0)
            self.raw_query_retry_wait = kwargs.get("raw_query_retry_wait", 3)

        return mock_init

    monkeypatch.setattr(DnsWalkHarness, "mock_data", mock_data)
    monkeypatch.setattr(DnsWalk, "__init__", init_wrapper(mock_data))
    monkeypatch.setattr(DnsWalk, "a_resolve", DnsWalkHarness.mock_a_resolve)
    monkeypatch.setattr(DnsWalk, "root_servers", ["127.0.0.1"])
    monkeypatch.setattr(dns.asyncquery, "udp_with_fallback", DnsWalkHarness.mock_udp_with_fallback)
