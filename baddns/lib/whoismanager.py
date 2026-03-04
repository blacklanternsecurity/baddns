import whois
import logging
import asyncio
import tldextract
from datetime import datetime, timezone, timedelta, date
from dateutil import parser as date_parser
from whois.exceptions import PywhoisError

log = logging.getLogger(__name__)

RESTRICTED_TLDS = {"gov", "mil", "edu", "int"}


class WhoisManager:
    _cache = {}

    def __init__(self, target):
        self.target = target
        self.whois_result = None

    @classmethod
    def clear_cache(cls):
        cls._cache.clear()

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
        log.debug(f"Submitting WHOIS query for {registered_domain}")
        try:
            w = await asyncio.to_thread(whois.whois, registered_domain, quiet=True)
            log.debug(f"Got response to whois request for {registered_domain}")
            self.whois_result = {"type": "response", "data": w}
        except PywhoisError as e:
            log.debug(f"Got PywhoisError for whois request for {registered_domain}")
            self.whois_result = {"type": "error", "data": str(e)}
        except Exception as e:
            log.debug(f"Got unknown error from whois: {str(e)}")
            self.whois_result = {"type": "error", "data": str(e)}
        self._cache[registered_domain] = self.whois_result

    def analyzeWHOIS(self):
        if not self.whois_result:
            return []
        if self.whois_result:
            whois_findings = []
            if self.whois_result["type"] == "error":
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
        else:
            log.debug("whois_result was NoneType")

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
