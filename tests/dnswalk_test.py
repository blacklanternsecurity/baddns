import pytest

from baddns.lib.dnswalk import DnsWalk

# Test for normal typical normal behavior

mock_data = {
    "ns_records": [
        {"127.0.0.1": {"answer": [], "authority": ["tld.dns.nameserver"]}},
        {"127.0.0.2": {"answer": [], "authority": ["ns1.bad.dns", "ns2.bad.dns"]}},
        {"127.0.0.3": {"answer": ["ns1.bad.dns"], "authority": []}},
        {"127.0.0.4": {"answer": ["ns2.bad.dns"], "authority": []}},
    ],
    "a_records": {"tld.dns.nameserver": "127.0.0.2", "ns1.bad.dns": "127.0.0.3", "ns2.bad.dns": "127.0.0.4"},
}


@pytest.mark.asyncio
@pytest.mark.parametrize("dnswalk_harness", [mock_data], indirect=True)
async def test_dnswalk_normal(dnswalk_harness):
    dnswalk = DnsWalk()
    ns_trace_results = await dnswalk.ns_trace("bad.dns")
    assert sorted(ns_trace_results) == ["ns1.bad.dns", "ns2.bad.dns"]


mock_data = {
    "ns_records": [{"127.0.0.1": {"answer": [], "authority": ["ns1.noresolve.dns", "ns2.noresolve.dns"]}}],
    "a_records": [],
}


# Test Nameservers don't resolve
@pytest.mark.asyncio
@pytest.mark.parametrize("dnswalk_harness", [mock_data], indirect=True)
async def test_dnswalk_nameserversdontresolve(dnswalk_harness):
    dnswalk = DnsWalk()
    ns_trace_results = await dnswalk.ns_trace("bad.dns")
    print(ns_trace_results)
    assert sorted(ns_trace_results) == ["ns1.noresolve.dns", "ns2.noresolve.dns"]


{
    "ns_records": [
        {"127.0.0.1": {"answer": [], "authority": ["ns1.noanswer.dns", "ns2.noanswer.dns"]}},
        {"127.0.0.2": {"answer": [], "authority": []}},
        {"127.0.0.3": {"answer": [], "authority": []}},
    ],
    "a_records": [{"ns1.noanswer.dns": "127.0.0.2"}, {"ns2.noanswer.dns": "127.0.0.3"}],
}


# Test Nameservers resolve but have no further answers
@pytest.mark.asyncio
@pytest.mark.parametrize("dnswalk_harness", [mock_data], indirect=True)
async def test_dnswalk_resolvewithnoanswers(dnswalk_harness):
    dnswalk = DnsWalk()
    ns_trace_results = await dnswalk.ns_trace("bad.dns")
    print(ns_trace_results)
    assert sorted(ns_trace_results) == ["ns1.noresolve.dns", "ns2.noresolve.dns"]


mock_data = {
    "ns_records": [
        {"127.0.0.1": {"answer": [], "authority": ["tld1.dns.nameserver", "tld2.dns.nameserver"]}},
        {"127.0.0.2": {"answer": [], "authority": ["ns1.finalanswer.dns", "ns2.finalanswer.dns"]}},
        {"127.0.0.3": {"answer": ["ns1.bad.dns"], "authority": []}},
        {"127.0.0.4": {"answer": ["ns2.bad.dns"], "authority": []}},
    ],
    "a_records": {
        "tld1.dns.nameserver": "127.0.0.2",
        "tld2.dns.nameserver": "127.0.0.3",
        "ns1.finalanswer.dns": "127.0.0.3",
        "ns2.finalanswer.dns": "127.0.0.4",
    },
}


# Test finding answer section at end of NS walk
@pytest.mark.asyncio
@pytest.mark.parametrize("dnswalk_harness", [mock_data], indirect=True)
async def test_dnswalk_answeratendofnschain(dnswalk_harness):
    dnswalk = DnsWalk()
    ns_trace_results = await dnswalk.ns_trace("bad.dns")
    print(ns_trace_results)
    assert sorted(ns_trace_results) == ["ns1.bad.dns", "ns2.bad.dns"]


mock_data = {
    "ns_records": [
        {"127.0.0.1": {"answer": [], "authority": ["ns1.badauthority.dns", "ns2.badauthority.dns"]}},
        {"127.0.0.2": {"answer": [], "authority": []}},
        {"127.0.0.3": {"answer": [], "authority": []}},
    ],
    "a_records": {"ns1.badauthority.dns": "127.0.0.2", "ns2.badauthority.dns": "127.0.0.3"},
}


# Test for an authority that doesn't lead anywhere
@pytest.mark.asyncio
@pytest.mark.parametrize("dnswalk_harness", [mock_data], indirect=True)
async def test_dnswalk_badauthority(dnswalk_harness):
    dnswalk = DnsWalk()
    ns_trace_results = await dnswalk.ns_trace("sub.bad.dns")
    print(ns_trace_results)
    assert ns_trace_results
    assert sorted(ns_trace_results) == ["ns1.badauthority.dns", "ns2.badauthority.dns"]


mock_data = {
    "soa_records": [{"ns-cloud-b1.googledomains.com": {"answer": [], "authority": ["bad.dns"]}}],
    "ns_records": [
        {"127.0.0.1": {"answer": [], "authority": ["e.gtld-servers.net"]}},
        {
            "e.gtld-servers.net": {
                "answer": [],
                "authority": [
                    "ns-cloud-b1.googledomains.com",
                ],
            }
        },
        {"ns-cloud-b1.googledomains.com": {"answer": [], "authority": []}},
    ],
    "a_records": {
        "e.gtld-servers.net": "192.168.1.2",
        "ns-cloud-b1.googledomains.com": "192.168.1.4",
        "bad.dns": "192.168.1.5",
        "root": "127.0.0.1",
    },
}


# should return no results, as there is an SOA at the end of the chain
@pytest.mark.asyncio
@pytest.mark.parametrize("dnswalk_harness", [mock_data], indirect=True)
async def test_dnswalk_subdomainnons(dnswalk_harness):
    dnswalk = DnsWalk()
    ns_trace_results = await dnswalk.ns_trace("sub.bad.dns")
    print(ns_trace_results)
    assert sorted(ns_trace_results) == []


mock_data = {
    "ns_records": [
        {"root": {"answer": [], "authority": ["a.gtld-servers.net", "b.gtld-servers.net", "c.gtld-servers.net"]}},
        {"a.gtld-servers.net": {"answer": [], "authority": ["ns1.bad.dns", "ns2.bad.dns"]}},
        {"ns1.bad.dns": {"answer": [], "authority": ["ns1.wordpress.com", "ns2.wordpress.com"]}},
        {"ns2.bad.dns": {"answer": [], "authority": []}},
        {"ns1.wordpress.com": {"answer": [], "authority": []}},
        {"ns2.wordpress.com": {"answer": [], "authority": []}},
    ],
    "a_records": {
        "a.gtld-servers.net": "192.168.2.2",
        "b.gtld-servers.net": "192.168.2.3",
        "c.gtld-servers.net": "192.168.2.4",
        "ns1.bad.dns": "192.168.3.1",
        "ns2.bad.dns": "192.168.3.2",
        "ns1.wordpress.com": "192.168.4.1",
        "ns2.wordpress.com": "192.168.4.2",
        "root": "127.0.0.1",
    },
}


# should ultimately find nameservers
@pytest.mark.asyncio
@pytest.mark.parametrize("dnswalk_harness", [mock_data], indirect=True)
async def test_dnswalk_subdomainfindns(dnswalk_harness):
    dnswalk = DnsWalk()
    ns_trace_results = await dnswalk.ns_trace("sub.bad.dns")
    print(ns_trace_results)
    assert ns_trace_results
    assert sorted(ns_trace_results) == ["ns1.wordpress.com", "ns2.wordpress.com"]
