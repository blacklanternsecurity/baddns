import sys


# Temporary workaround for: https://github.com/blacklanternsecurity/baddns/issues/402
class noop:
    def __getattr__(self, item):
        def method(*args, **kwargs):
            pass  # Method does nothing

        return method


sys.modules["imp"] = noop()

import os
from contextlib import contextmanager


# Another temporary workaround until https://github.com/richardpenman/whois gets updated version pushed to pypi :( :( :(
@contextmanager
def suppress_stdout():
    original_stdout = sys.stdout
    sys.stdout = open(os.devnull, "w")
    try:
        yield
    finally:
        sys.stdout = original_stdout


import whois
import logging
import asyncio
import tldextract
from datetime import date, datetime, timedelta
from dateutil import parser as date_parser


log = logging.getLogger(__name__)


class WhoisManager:
    def __init__(self, target):
        self.target = target
        self.whois_result = None

    async def dispatchWHOIS(self):
        ext = tldextract.extract(self.target)
        log.debug(f"Extracted base domain [{ext.registered_domain}] from [{self.target}]")
        log.debug(f"Submitting WHOIS query for {ext.registered_domain}")
        try:
            with suppress_stdout():
                w = await asyncio.to_thread(whois.whois, ext.registered_domain)
            log.debug(f"Got response to whois request for {ext.registered_domain}")
            self.whois_result = {"type": "response", "data": w}
        except whois.parser.PywhoisError as e:
            log.debug(f"Got PywhoisError for whois request for {ext.registered_domain}")
            self.whois_result = {"type": "error", "data": str(e)}

    def analyzeWHOIS(self):
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
                    expiration_date = max(expiration_data)
                else:
                    expiration_date = expiration_data

                expiration_date = self.date_parse(expiration_date)
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
