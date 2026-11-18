import json
import whois
import logging
import asyncio
import tldextract
from blasthttp import BlastHTTP
from datetime import datetime, timezone, timedelta, date
from dateutil import parser as date_parser
from whois.exceptions import PywhoisError, WhoisDomainNotFoundError

from baddns.lib.httpmanager import USER_AGENT

log = logging.getLogger(__name__)

RESTRICTED_TLDS = {"gov", "mil", "edu", "int"}

# IANA's list of which RDAP server answers for each TLD (RFC 9224)
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
# A few quick tries, then WHOIS only for the rest of the run (worst case about 17 seconds, once)
RDAP_BOOTSTRAP_ATTEMPTS = 3
RDAP_BOOTSTRAP_TIMEOUT = 5
RDAP_BOOTSTRAP_RETRY_WAIT = 1
RDAP_TIMEOUT = 10


def parse_rdap_bootstrap(data):
    """Map each TLD in IANA's RDAP bootstrap file to its RDAP base URL, preferring https."""
    servers = {}
    if not isinstance(data, dict):
        return servers
    for service in data.get("services") or []:
        if not isinstance(service, list) or len(service) < 2:
            continue
        tlds, urls = service[0], service[1]
        if not isinstance(tlds, list) or not isinstance(urls, list):
            continue
        urls = [u for u in urls if isinstance(u, str) and u]
        url = next((u for u in urls if u.lower().startswith("https://")), None) or next(iter(urls), None)
        if not url:
            continue
        for tld in tlds:
            if isinstance(tld, str) and tld:
                servers[tld.lower()] = url
    return servers


class WhoisManager:
    """Registration lookups: RDAP first, falling back to WHOIS for TLDs without RDAP or when RDAP gives no answer."""

    _cache = {}
    # TLD -> RDAP base URL, loaded once per process. None means not loaded yet; {} means unavailable (WHOIS only).
    _rdap_servers = None
    _rdap_lock = None
    _rdap_lock_loop = None

    def __init__(self, target, http_client=None):
        self.target = target
        self.http_client = http_client
        self.whois_result = None

    @classmethod
    def clear_cache(cls):
        cls._cache.clear()

    @property
    def source(self):
        """Which lookup produced the result: "RDAP", "WHOIS", or None when there is no result."""
        if not self.whois_result:
            return None
        return self.whois_result.get("source", "WHOIS")

    @classmethod
    def _get_rdap_lock(cls):
        # asyncio locks belong to one event loop, so make a new one if the loop changed
        loop = asyncio.get_running_loop()
        if cls._rdap_lock is None or cls._rdap_lock_loop is not loop:
            cls._rdap_lock = asyncio.Lock()
            cls._rdap_lock_loop = loop
        return cls._rdap_lock

    @staticmethod
    async def _fetch_rdap_bootstrap(http_client):
        """One attempt at downloading IANA's bootstrap file. Returns the server map, or {} if it failed."""
        try:
            response = await http_client.request(
                RDAP_BOOTSTRAP_URL,
                method="GET",
                headers=[("User-Agent", USER_AGENT), ("Accept", "application/json")],
                timeout=RDAP_BOOTSTRAP_TIMEOUT,
                verify_certs=True,
                follow_redirects=True,
            )
        except Exception as e:
            log.debug(f"RDAP bootstrap fetch failed: {e}")
            return {}
        if response.status != 200:
            log.debug(f"RDAP bootstrap fetch returned status {response.status}")
            return {}
        try:
            return parse_rdap_bootstrap(json.loads(response.body))
        except ValueError as e:
            log.debug(f"RDAP bootstrap was not valid JSON: {e}")
            return {}

    @classmethod
    async def _get_rdap_servers(cls, http_client):
        if cls._rdap_servers is not None:
            return cls._rdap_servers
        async with cls._get_rdap_lock():
            if cls._rdap_servers is None:
                servers = {}
                for attempt in range(1, RDAP_BOOTSTRAP_ATTEMPTS + 1):
                    servers = await cls._fetch_rdap_bootstrap(http_client)
                    if servers:
                        break
                    if attempt < RDAP_BOOTSTRAP_ATTEMPTS:
                        log.debug(
                            f"RDAP bootstrap attempt {attempt} of {RDAP_BOOTSTRAP_ATTEMPTS} failed, "
                            f"retrying in {RDAP_BOOTSTRAP_RETRY_WAIT}s"
                        )
                        await asyncio.sleep(RDAP_BOOTSTRAP_RETRY_WAIT)
                if servers:
                    log.debug(f"Loaded RDAP servers for {len(servers)} TLDs")
                else:
                    log.debug(f"RDAP bootstrap unavailable after {RDAP_BOOTSTRAP_ATTEMPTS} attempts, using WHOIS only")
                cls._rdap_servers = servers
        return cls._rdap_servers

    @staticmethod
    def _rdap_server_for(servers, suffix):
        """Find the RDAP server for a public suffix, trying the longest match first (co.uk, then uk)."""
        labels = suffix.lower().split(".") if suffix else []
        for i in range(len(labels)):
            server = servers.get(".".join(labels[i:]))
            if server:
                return server
        return None

    async def _lookup_rdap(self, suffix, registered_domain):
        """Return a result built from RDAP, or None when RDAP isn't available or gave no usable answer."""
        if not suffix:
            return None
        http_client = self.http_client if self.http_client is not None else BlastHTTP()
        server = self._rdap_server_for(await self._get_rdap_servers(http_client), suffix)
        if not server:
            log.debug(f"No RDAP server for [{suffix}], using WHOIS")
            return None

        url = f"{server.rstrip('/')}/domain/{registered_domain}"
        log.debug(f"Submitting RDAP query: {url}")
        try:
            response = await http_client.request(
                url,
                method="GET",
                headers=[("User-Agent", USER_AGENT), ("Accept", "application/rdap+json")],
                timeout=RDAP_TIMEOUT,
                verify_certs=True,
                follow_redirects=True,
            )
        except Exception as e:
            log.debug(f"RDAP request to {url} failed: {e}")
            return None

        # 404 is the registry saying the domain does not exist. Anything else that isn't a domain object
        # (rate limits, server errors, odd bodies) proves nothing, so it falls back to WHOIS.
        if response.status == 404:
            log.debug(f"RDAP says {registered_domain} is not registered")
            return {"type": "unregistered", "source": "RDAP", "data": f"RDAP 404 from {url}"}
        if response.status != 200:
            log.debug(f"RDAP query for {registered_domain} returned status {response.status}")
            return None
        try:
            data = json.loads(response.body)
        except ValueError:
            log.debug(f"RDAP response for {registered_domain} was not JSON")
            return None
        if not isinstance(data, dict) or data.get("objectClassName") != "domain":
            log.debug(f"RDAP response for {registered_domain} was not a domain object")
            return None

        expiration = next(
            (
                event.get("eventDate")
                for event in data.get("events") or []
                if isinstance(event, dict) and event.get("eventAction") == "expiration"
            ),
            None,
        )
        log.debug(f"RDAP says {registered_domain} is registered (expiration: {expiration})")
        return {"type": "response", "source": "RDAP", "data": {"expiration_date": expiration}}

    async def _lookup_whois(self, registered_domain):
        log.debug(f"Submitting WHOIS query for {registered_domain}")
        try:
            w = await asyncio.to_thread(whois.whois, registered_domain, quiet=True)
            log.debug(f"Got response to whois request for {registered_domain}")
            return {"type": "response", "source": "WHOIS", "data": w}
        except WhoisDomainNotFoundError as e:
            # python-whois recognized the registry's "not found" reply for this TLD
            log.debug(f"WHOIS says {registered_domain} is not registered")
            return {"type": "unregistered", "source": "WHOIS", "data": str(e)}
        except PywhoisError as e:
            log.debug(f"Got PywhoisError for whois request for {registered_domain}")
            return {"type": "error", "source": "WHOIS", "data": str(e)}
        except Exception as e:
            log.debug(f"Got unknown error from whois: {str(e)}")
            return {"type": "error", "source": "WHOIS", "data": str(e)}

    async def dispatchWHOIS(self):
        ext = tldextract.extract(self.target)
        if ext.registered_domain == "" or ext.registered_domain == None:
            registered_domain = self.target
        else:
            registered_domain = ext.registered_domain

        # Skip WHOIS for restricted TLDs (.gov, .mil, .edu, .int)
        tld = ext.suffix.lower().split(".")[-1] if ext.suffix else ""
        if tld in RESTRICTED_TLDS:
            log.debug(f"Skipping WHOIS for restricted TLD [{ext.suffix}] domain [{registered_domain}]")
            self.whois_result = None
            return

        # Guard against empty/invalid domains
        if not registered_domain or "." not in registered_domain:
            log.debug(f"Skipping WHOIS for invalid domain [{registered_domain}] from [{self.target}]")
            self.whois_result = {"type": "error", "data": "Invalid domain for WHOIS"}
            return

        if registered_domain in self._cache:
            log.debug(f"Using cached WHOIS result for {registered_domain}")
            self.whois_result = self._cache[registered_domain]
            return

        log.debug(f"Extracted base domain [{registered_domain}] from [{self.target}]")
        self.whois_result = await self._lookup_rdap(ext.suffix, registered_domain)
        if self.whois_result is None:
            self.whois_result = await self._lookup_whois(registered_domain)
        self._cache[registered_domain] = self.whois_result

    def analyzeWHOIS(self):
        if not self.whois_result:
            return []
        if self.whois_result:
            whois_findings = []
            if self.whois_result["type"] == "unregistered":
                log.debug(f"{self.source} result says the domain is unregistered")
                whois_findings.append("unregistered")

            elif self.whois_result["type"] == "error":
                log.debug("whois result was an error")
                if "No match for" in self.whois_result["data"]:
                    whois_findings.append("unregistered")

            elif self.whois_result["type"] == "response":
                log.debug("whois resulted in a response")
                expiration_data = self.whois_result.get("data", {}).get("expiration_date", None)

                if isinstance(expiration_data, list):
                    log.debug("Expiration data:")
                    log.debug(expiration_data)
                    log.debug("Got multiple expiration dates. Falling back to the latest...")

                    normalized_dates = [
                        self.normalize_date(self.date_parse(date)) for date in expiration_data if self.date_parse(date)
                    ]
                    expiration_date = max(normalized_dates) if normalized_dates else None

                else:
                    expiration_date = self.date_parse(expiration_data)
                    if expiration_date:
                        expiration_date = self.normalize_date(expiration_date)

                if expiration_date:
                    current_date = date.today()
                    expiration_plus_one = expiration_date.date() + timedelta(days=1)
                    if expiration_plus_one < current_date:
                        log.debug(
                            f"Current Date (minus one) ({current_date.strftime('%Y-%m-%d')}) is after Expiration Date ({expiration_date.date().strftime('%Y-%m-%d')})"
                        )
                        whois_findings.append(
                            f"Registration Expired (Expiration: [{expiration_date.strftime('%Y-%m-%d %H:%M:%S')}]"
                        )
                    else:
                        log.debug(f"Domain {self.target} is not expired")
            return whois_findings

    @staticmethod
    def date_parse(unknown_date):
        # Check if it's already a datetime object
        if isinstance(unknown_date, datetime):
            return unknown_date

        # If it's a string, try to parse it
        if isinstance(unknown_date, str):
            try:
                return date_parser.parse(unknown_date)
            except ValueError as e:
                log.debug(f"Failed to parse date from string: {unknown_date}. Error: {e}")
                return None

        log.debug(f"Unsupported date object type: {type(unknown_date)}. Value: {unknown_date}")
        return None

    @staticmethod
    def normalize_date(date):
        if date.tzinfo is None:
            return date.replace(tzinfo=timezone.utc)
        else:
            return date.astimezone(timezone.utc)
