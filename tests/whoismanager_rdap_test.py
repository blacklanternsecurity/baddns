import json
import asyncio
import datetime
import pytest
from unittest.mock import patch
from whois.exceptions import WhoisDomainNotFoundError

from baddns.lib import whoismanager
from baddns.lib.whoismanager import WhoisManager, parse_rdap_bootstrap, RDAP_BOOTSTRAP_URL, RDAP_BOOTSTRAP_ATTEMPTS
from baddns.mock_blasthttp import MockBlastHTTP
from baddns.modules.references import BadDNS_references
from baddns.modules.cname import BadDNS_cname
from baddns.lib.loader import load_signatures
from .helpers import mock_signature_load

RDAP_BASE = "https://rdap.example.test/rdap/"
RDAP_DOMAIN_URL = f"{RDAP_BASE}domain/abandoned-vendor.tech"


class CountingMockBlastHTTP(MockBlastHTTP):
    """MockBlastHTTP that records every URL requested and yields to the event loop like a real request."""

    def __init__(self):
        super().__init__()
        self.requested = []

    async def request(self, url, method="GET", **kwargs):
        self.requested.append(url)
        await asyncio.sleep(0)
        return await super().request(url, method=method, **kwargs)


def rdap_domain(expiration=None):
    events = [{"eventAction": "registration", "eventDate": "2015-01-01T00:00:00Z"}]
    if expiration:
        events.append({"eventAction": "expiration", "eventDate": expiration})
    return json.dumps({"objectClassName": "domain", "ldhName": "abandoned-vendor.tech", "events": events})


@pytest.fixture
def client():
    return CountingMockBlastHTTP()


@pytest.fixture
def rdap_servers(monkeypatch):
    monkeypatch.setattr(WhoisManager, "_rdap_servers", {"tech": RDAP_BASE})


@pytest.fixture(autouse=True)
def fresh_cache(monkeypatch):
    WhoisManager.clear_cache()
    monkeypatch.setattr(WhoisManager, "_rdap_lock", None)
    monkeypatch.setattr(WhoisManager, "_rdap_lock_loop", None)
    monkeypatch.setattr(whoismanager, "RDAP_BOOTSTRAP_RETRY_WAIT", 0)
    yield
    WhoisManager.clear_cache()


def test_parse_rdap_bootstrap():
    data = {
        "services": [
            [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
            [["TECH"], ["http://rdap.radix.host/rdap/", "https://rdap.radix.host/rdap/"]],
            [["onlyhttp"], ["http://rdap.onlyhttp.test/"]],
            "garbage",
            [["short"]],
            [["notalist"], "https://rdap.notalist.test/"],
            [["nourls"], []],
            [[None, "ok"], ["", "https://rdap.ok.test/"]],
        ]
    }
    assert parse_rdap_bootstrap(data) == {
        "com": "https://rdap.verisign.com/com/v1/",
        "net": "https://rdap.verisign.com/com/v1/",
        "tech": "https://rdap.radix.host/rdap/",
        "onlyhttp": "http://rdap.onlyhttp.test/",
        "ok": "https://rdap.ok.test/",
    }
    assert parse_rdap_bootstrap("not a dict") == {}
    assert parse_rdap_bootstrap({"services": None}) == {}


def test_rdap_server_for_longest_suffix_first():
    assert WhoisManager._rdap_server_for({"uk": "U"}, "co.uk") == "U"
    assert WhoisManager._rdap_server_for({"uk": "U", "co.uk": "CU"}, "co.uk") == "CU"
    assert WhoisManager._rdap_server_for({"uk": "U"}, "CO.UK") == "U"
    assert WhoisManager._rdap_server_for({"uk": "U"}, "io") is None
    assert WhoisManager._rdap_server_for({"uk": "U"}, "") is None


@pytest.mark.asyncio
async def test_rdap_404_is_unregistered(client, rdap_servers):
    client.add_response(url=RDAP_DOMAIN_URL, status=404, body='{"errorCode": 404}')
    with patch("whois.whois") as mock_whois:
        manager = WhoisManager("cdn.abandoned-vendor.tech", http_client=client)
        await manager.dispatchWHOIS()
        assert not mock_whois.called

    assert manager.analyzeWHOIS() == ["unregistered"]
    assert manager.source == "RDAP"
    assert client.requested == [RDAP_DOMAIN_URL]

    # same registered domain comes from the cache, no second request
    cached = WhoisManager("www.abandoned-vendor.tech", http_client=client)
    await cached.dispatchWHOIS()
    assert cached.analyzeWHOIS() == ["unregistered"]
    assert client.requested == [RDAP_DOMAIN_URL]


@pytest.mark.asyncio
async def test_rdap_expired_registration(client, rdap_servers):
    client.add_response(url=RDAP_DOMAIN_URL, status=200, body=rdap_domain(expiration="2020-01-01T00:00:00Z"))
    with patch("whois.whois") as mock_whois:
        manager = WhoisManager("abandoned-vendor.tech", http_client=client)
        await manager.dispatchWHOIS()
        assert not mock_whois.called

    findings = manager.analyzeWHOIS()
    assert len(findings) == 1
    assert findings[0].startswith("Registration Expired (Expiration: [2020-01-01")
    assert manager.source == "RDAP"


@pytest.mark.asyncio
async def test_rdap_active_registration(client, rdap_servers):
    future = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)).isoformat()
    client.add_response(url=RDAP_DOMAIN_URL, status=200, body=rdap_domain(expiration=future))
    manager = WhoisManager("abandoned-vendor.tech", http_client=client)
    await manager.dispatchWHOIS()
    assert manager.analyzeWHOIS() == []
    assert manager.source == "RDAP"


@pytest.mark.asyncio
async def test_rdap_registered_without_expiration_event(client, rdap_servers):
    client.add_response(url=RDAP_DOMAIN_URL, status=200, body=rdap_domain())
    with patch("whois.whois") as mock_whois:
        manager = WhoisManager("abandoned-vendor.tech", http_client=client)
        await manager.dispatchWHOIS()
        assert not mock_whois.called
    assert manager.analyzeWHOIS() == []
    assert manager.source == "RDAP"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status, body",
    [
        (429, ""),
        (500, ""),
        (200, "<html>not json</html>"),
        (200, json.dumps({"objectClassName": "entity"})),
        (200, json.dumps([1, 2, 3])),
        (None, None),  # nothing registered: the request raises
    ],
)
async def test_rdap_without_an_answer_falls_back_to_whois(client, rdap_servers, status, body):
    if status is not None:
        client.add_response(url=RDAP_DOMAIN_URL, status=status, body=body)
    with patch("whois.whois") as mock_whois:
        mock_whois.return_value = {"domain_name": "abandoned-vendor.tech", "expiration_date": None}
        manager = WhoisManager("abandoned-vendor.tech", http_client=client)
        await manager.dispatchWHOIS()
        mock_whois.assert_called_once()

    assert client.requested == [RDAP_DOMAIN_URL]
    assert manager.whois_result["type"] == "response"
    assert manager.source == "WHOIS"
    assert manager.analyzeWHOIS() == []


@pytest.mark.asyncio
async def test_tld_without_rdap_uses_whois(client, rdap_servers):
    with patch("whois.whois") as mock_whois:
        mock_whois.side_effect = WhoisDomainNotFoundError("Domain not found.")
        manager = WhoisManager("vendor.io", http_client=client)
        await manager.dispatchWHOIS()
        mock_whois.assert_called_once()

    assert client.requested == []
    assert manager.analyzeWHOIS() == ["unregistered"]
    assert manager.source == "WHOIS"


@pytest.mark.asyncio
async def test_unknown_suffix_skips_rdap(client, monkeypatch):
    # tldextract finds no public suffix, so there is no TLD to look up an RDAP server for
    monkeypatch.setattr(WhoisManager, "_rdap_servers", {"notarealtld": RDAP_BASE})
    with patch("whois.whois") as mock_whois:
        mock_whois.return_value = {"domain_name": None}
        manager = WhoisManager("host.notarealtld", http_client=client)
        await manager.dispatchWHOIS()
        mock_whois.assert_called_once()
    assert client.requested == []
    assert manager.source == "WHOIS"


@pytest.mark.asyncio
async def test_whois_domain_not_found_error_is_unregistered():
    # .org, .io and .de reply "Domain not found." (or similar), which python-whois raises as WhoisDomainNotFoundError
    with patch("whois.whois") as mock_whois:
        mock_whois.side_effect = WhoisDomainNotFoundError("Domain not found.")
        manager = WhoisManager("unregistered-example.org")
        await manager.dispatchWHOIS()

    assert manager.whois_result["type"] == "unregistered"
    assert manager.analyzeWHOIS() == ["unregistered"]
    assert manager.source == "WHOIS"


@pytest.mark.asyncio
async def test_bootstrap_fetched_once_for_concurrent_lookups(client, monkeypatch):
    monkeypatch.setattr(WhoisManager, "_rdap_servers", None)
    bootstrap = {"services": [[["tech", "online"], [RDAP_BASE]]]}
    client.add_response(url=RDAP_BOOTSTRAP_URL, status=200, body=json.dumps(bootstrap))
    domains = [f"vendor{i}.tech" for i in range(4)] + ["vendor.online"]
    for domain in domains:
        client.add_response(url=f"{RDAP_BASE}domain/{domain}", status=404)

    managers = [WhoisManager(domain, http_client=client) for domain in domains]
    with patch("whois.whois") as mock_whois:
        await asyncio.gather(*(m.dispatchWHOIS() for m in managers))
        assert not mock_whois.called

    assert client.requested.count(RDAP_BOOTSTRAP_URL) == 1
    assert WhoisManager._rdap_servers == {"tech": RDAP_BASE, "online": RDAP_BASE}
    assert all(m.analyzeWHOIS() == ["unregistered"] for m in managers)


@pytest.mark.asyncio
@pytest.mark.parametrize("status, body", [(500, ""), (200, "not json"), (None, None)])
async def test_bootstrap_failure_means_whois_only(client, monkeypatch, status, body):
    monkeypatch.setattr(WhoisManager, "_rdap_servers", None)
    if status is not None:
        client.add_response(url=RDAP_BOOTSTRAP_URL, status=status, body=body)

    with patch("whois.whois") as mock_whois:
        mock_whois.return_value = {"domain_name": "x"}
        for domain in ["abandoned-vendor.tech", "another.tech"]:
            manager = WhoisManager(domain, http_client=client)
            await manager.dispatchWHOIS()
            assert manager.source == "WHOIS"
        assert mock_whois.call_count == 2

    # a few quick attempts, then it gives up for the rest of the run instead of retrying for every domain
    assert client.requested == [RDAP_BOOTSTRAP_URL] * RDAP_BOOTSTRAP_ATTEMPTS
    assert WhoisManager._rdap_servers == {}


@pytest.mark.asyncio
async def test_bootstrap_recovers_on_retry(client, monkeypatch):
    monkeypatch.setattr(WhoisManager, "_rdap_servers", None)
    client.add_response(url=RDAP_BOOTSTRAP_URL, status=503)
    client.add_response(url=RDAP_BOOTSTRAP_URL, status=200, body=json.dumps({"services": [[["tech"], [RDAP_BASE]]]}))
    client.add_response(url=RDAP_DOMAIN_URL, status=404)

    with patch("whois.whois") as mock_whois:
        manager = WhoisManager("abandoned-vendor.tech", http_client=client)
        await manager.dispatchWHOIS()
        assert not mock_whois.called

    assert client.requested == [RDAP_BOOTSTRAP_URL, RDAP_BOOTSTRAP_URL, RDAP_DOMAIN_URL]
    assert manager.source == "RDAP"
    assert manager.analyzeWHOIS() == ["unregistered"]


@pytest.mark.asyncio
async def test_restricted_tld_skips_rdap_and_whois(client, monkeypatch):
    monkeypatch.setattr(WhoisManager, "_rdap_servers", {"gov": RDAP_BASE})
    with patch("whois.whois") as mock_whois:
        manager = WhoisManager("example.gov", http_client=client)
        await manager.dispatchWHOIS()
        assert not mock_whois.called
    assert client.requested == []
    assert manager.whois_result is None
    assert manager.source is None
    assert manager.analyzeWHOIS() == []


@pytest.mark.asyncio
async def test_default_http_client_is_used_without_one(client, rdap_servers):
    client.add_response(url=RDAP_DOMAIN_URL, status=404)
    with patch("baddns.lib.whoismanager.BlastHTTP", return_value=client):
        manager = WhoisManager("abandoned-vendor.tech")
        await manager.dispatchWHOIS()
    assert client.requested == [RDAP_DOMAIN_URL]
    assert manager.analyzeWHOIS() == ["unregistered"]


def test_source_for_results_without_one():
    manager = WhoisManager("example.com")
    assert manager.source is None
    manager.whois_result = {"type": "error", "data": "No match for"}
    assert manager.source == "WHOIS"


@pytest.mark.asyncio
async def test_rdap_lock_is_replaced_for_a_new_event_loop():
    stale = asyncio.Lock()
    WhoisManager._rdap_lock = stale
    WhoisManager._rdap_lock_loop = object()
    lock = WhoisManager._get_rdap_lock()
    assert lock is not stale
    assert WhoisManager._get_rdap_lock() is lock


@pytest.mark.asyncio
async def test_references_flags_unregistered_domain_via_rdap(
    fs, configure_mock_resolver, cached_suffix_list, monkeypatch
):
    """A page loads script from a domain nobody owns; RDAP's 404 turns that into a finding."""
    monkeypatch.setattr(WhoisManager, "_rdap_servers", {"tech": RDAP_BASE})
    mock_data = {"bad.dns": {"A": ["127.0.0.1"]}, "_NXDOMAIN": ["cdn.abandoned-vendor.tech"]}
    mock_resolver = configure_mock_resolver(mock_data)
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")

    http = CountingMockBlastHTTP()
    http.add_response(
        url="http://bad.dns/",
        status=200,
        body='<html><head><script src="https://cdn.abandoned-vendor.tech/loader.js"></script></head></html>',
    )
    http.add_response(url=RDAP_DOMAIN_URL, status=404)

    references = BadDNS_references(
        "bad.dns", signatures=load_signatures("/tmp/signatures"), dns_client=mock_resolver, http_client=http
    )
    with patch("whois.whois") as mock_whois:
        assert await references.dispatch()
        findings = [f.to_dict() for f in references.analyze()]
        assert not mock_whois.called

    assert findings == [
        {
            "target": "bad.dns",
            "description": "Hijackable reference, JS Include [cdn.abandoned-vendor.tech]. Original Event: [CNAME unregistered]",
            "confidence": "CONFIRMED",
            "severity": "MEDIUM",
            "signature": "CNAME Takeover",
            "indicator": "Whois Data",
            "trigger": "Javascript Source: [https://cdn.abandoned-vendor.tech/loader.js], Original Trigger: [cdn.abandoned-vendor.tech] Direct Mode: [True]",
            "module": "references",
            "data_source": "RDAP",
        }
    ]


@pytest.mark.asyncio
async def test_finding_reads_the_same_whichever_lookup_answered(
    fs, configure_mock_resolver, cached_suffix_list, monkeypatch
):
    """Only data_source differs, so BBOT (which builds its description from the other fields) dedupes them."""
    mock_resolver = configure_mock_resolver({"_NXDOMAIN": ["abandoned-vendor.tech"]})
    mock_signature_load(fs, "nucleitemplates_azure-takeover-detection.yml")
    signatures = load_signatures("/tmp/signatures")

    async def finding_for(rdap_servers, http):
        WhoisManager.clear_cache()
        monkeypatch.setattr(WhoisManager, "_rdap_servers", rdap_servers)
        cname = BadDNS_cname(
            "abandoned-vendor.tech",
            signatures=signatures,
            dns_client=mock_resolver,
            http_client=http,
            direct_mode=True,
        )
        assert await cname.dispatch()
        findings = [f.to_dict() for f in cname.analyze()]
        assert len(findings) == 1
        return findings[0]

    rdap_http = CountingMockBlastHTTP()
    rdap_http.add_response(url=RDAP_DOMAIN_URL, status=404)
    via_rdap = await finding_for({"tech": RDAP_BASE}, rdap_http)

    with patch("whois.whois", side_effect=WhoisDomainNotFoundError("Domain not found.")):
        via_whois = await finding_for({}, CountingMockBlastHTTP())

    assert via_rdap.pop("data_source") == "RDAP"
    assert via_whois.pop("data_source") == "WHOIS"
    assert via_rdap == via_whois
    assert via_rdap["indicator"] == "Whois Data"
