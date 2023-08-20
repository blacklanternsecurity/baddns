import whois
import logging
import tldextract

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
            w = whois.whois(ext.registered_domain)
            log.debug(f"Got response to whois request for {ext.registered_domain}")
            self.whois_result = {"type": "response", "data": w}
        except whois.parser.PywhoisError as e:
            log.debug(f"Got PywhoisError for whois request for {ext.registered_domain}")
            self.whois_result = {"type": "error", "data": str(e)}
