import re

from baddns.base import BadDNS_base
from baddns.lib.dnsmanager import DNSManager
from baddns.lib.httpmanager import HttpManager
from baddns.modules.cname import BadDNS_cname
from baddns.lib.findings import Finding

import logging
from urllib.parse import urlparse

log = logging.getLogger(__name__)


class BadDNS_references(BadDNS_base):
    name = "references"
    description = "Check HTML content for links or other references that contain a hijackable domain"

    regex_jssrc = re.compile(r'<script[^>]*src\s*=\s*[\'"]([^\'">]+)[\'"]', re.IGNORECASE)
    regex_csssrc = re.compile(r'<link[^>]*href\s*=\s*[\'"]([^\'">]+)[\'"]', re.IGNORECASE)
    regex_csp = re.compile(r"Content-Security-Policy: (.+?)\|", re.IGNORECASE)
    regex_cors = re.compile(r"Access-Control-Allow-Origin: (.+?)\|", re.IGNORECASE)
    regex_domain_url = re.compile(
        r"(?:((?:https?:\/\/)?(?:\w(?:[\w-]{0,100}\w)?\.)+(?:[xX][nN]--)?[^\W_]{0,63}\.?))(?!(\/|\?))", re.IGNORECASE
    )

    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)
        self.target = target
        self.target_dnsmanager = DNSManager(
            target, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers
        )
        self.target_httpmanager = HttpManager(
            self.target, http_client_class=self.http_client_class, skip_redirects=True
        )
        self.cname_findings = None
        self.cname_findings_direct = None
        self.reference_data = {}

    def extract_domains_headers(self, header_name, regex, headers_str, description):
        log.debug(f"Searching for {header_name} in headers...")

        results = []
        match = regex.search(headers_str)
        if match:
            log.debug(f"Found {header_name} header, extracting domains...")
            header_string = match.group(1)
            log.debug(f"Extracted {header_name} content: {header_string}")

            extracted_domains = []
            domain_url_matches = re.finditer(self.regex_domain_url, header_string)

            for domain_url in domain_url_matches:
                domain_or_url = domain_url.group(1)
                if domain_or_url:
                    if not domain_or_url.startswith(("http://", "https://")):
                        url = f"https://{domain_or_url}"
                    else:
                        url = domain_or_url
                    parsed_url = urlparse(url)
                    domain = parsed_url.netloc
                    if domain not in extracted_domains:
                        log.debug(f"Extracted domain: {domain}")
                        extracted_domains.append(domain)
                        results.append(
                            {
                                "url": domain_or_url,
                                "domain": domain,
                                "description": f"Hijackable reference, {description} [{domain}]",
                                "trigger": f"{header_name} Header: [{domain_or_url}]",
                            }
                        )
                    else:
                        log.debug(f"Duplicate domain {domain} ignored.")
                else:
                    log.debug("Failed to extract domain properly from header")
            log.debug(
                f"Finished extracting domains from {header_name}. Found {len(extracted_domains)} unique domain(s)."
            )
        else:
            log.debug(f"{header_name} header not found.")

        return results

    def parse_headers(self, headers):
        log.debug("Starting to parse headers")
        headers_str = "|".join(f"{key}: {value}" for key, value in headers.items())
        log.debug(f"Formatted headers string: {headers_str}")

        results = []
        results.extend(
            self.extract_domains_headers("Content-Security-Policy", self.regex_csp, headers_str, "CSP domain")
        )
        results.extend(
            self.extract_domains_headers(
                "Access-Control-Allow-Origin", self.regex_cors, headers_str, "CORS header domain"
            )
        )
        log.debug(f"Completed parsing headers. Total results: {len(results)}")
        return results

    def extract_domains_body(self, body, regex, description, source):
        results = []
        for match in regex.finditer(body):
            url = match.group(1)
            parsed_url = urlparse(url)
            # this was a relative link, and therefore not relevant for us
            if parsed_url.scheme == "" and parsed_url.netloc == "":
                log.debug(f"URL was relative, ignoring: [{url}]")
                continue
            domain = parsed_url.netloc
            results.append(
                {
                    "url": url,
                    "domain": domain,
                    "description": f"Hijackable reference, {description} [{domain}]",
                    "trigger": f"{source}: [{url}]",
                }
            )
        return results

    def parse_body(self, body):
        log.debug("Starting to parse body content for JS and CSS sources...")
        results = []

        # Extract domains from JS sources
        log.debug("Looking for JS includes...")
        js_results = self.extract_domains_body(body, self.regex_jssrc, "JS Include", "Javascript Source")
        if js_results:
            log.debug(f"Found {len(js_results)} domain(s) in JS includes.")
        results.extend(js_results)

        # Extract domains from CSS sources
        log.debug("Looking for CSS includes...")
        css_results = self.extract_domains_body(body, self.regex_csssrc, "CSS Include", "CSS Source")
        if css_results:
            log.debug(f"Found {len(css_results)} domain(s) in CSS includes.")
        results.extend(css_results)

        log.debug(f"Completed parsing body content. Total results: {len(results)}")
        return results

    async def process_cname_analysis(self, parsed_results):
        cname_findings = []
        for pr in parsed_results:
            if pr["domain"] == self.target:
                log.debug(f"Found domain matches target ({self.target}), ignoring")
                continue
            log.debug(f"Initializing cname instance for target {pr['domain']}")

            for direct_mode in [True, False]:
                cname_instance = BadDNS_cname(
                    pr["domain"],
                    custom_nameservers=self.custom_nameservers,
                    signatures=self.signatures,
                    direct_mode=direct_mode,
                    parent_class="references",
                    http_client_class=self.http_client_class,
                    dns_client=self.dns_client,
                )
                if await cname_instance.dispatch():
                    finding = {
                        "finding": cname_instance.analyze(),
                        "description": pr["description"],
                        "trigger": pr["trigger"],
                        "direct_mode": direct_mode,
                    }
                    cname_findings.append(finding)
                await cname_instance.cleanup()
        return cname_findings

    async def dispatch(self):
        log.debug("in references dispatch")
        await self.target_httpmanager.dispatchHttp()
        log.debug("HTTP dispatch complete")

        live_results = [
            getattr(self.target_httpmanager, f"{protocol}_denyredirects_results")
            for protocol in ["http", "https"]
            if getattr(self.target_httpmanager, f"{protocol}_denyredirects_results")
        ]

        parsed_results = []
        for r in live_results:
            parsed_results.extend(self.parse_headers(r.headers))
            parsed_results.extend(self.parse_body(r.text))

        self.cname_findings_direct = await self.process_cname_analysis(parsed_results)
        return True

    def _convert_findings(self, finding_sets):
        converted_findings = []
        for finding_set in finding_sets:
            for finding in finding_set["finding"]:
                finding_dict = finding.to_dict()
                log.debug(f"Found finding during cname check for target: {finding_dict['target']}")
                converted_findings.append(
                    Finding(
                        {
                            "target": self.target,
                            "description": f"{finding_set['description']}. Original Event: [{finding_dict['description']}]",
                            "confidence": finding_dict["confidence"],
                            "signature": finding_dict["signature"],
                            "indicator": finding_dict["indicator"],
                            "trigger": f'{finding_set["trigger"]}, Original Trigger: [{finding_dict["trigger"]}] Direct Mode: [{str(finding_set["direct_mode"])}]',
                            "module": type(self),
                        }
                    )
                )
        return converted_findings

    def analyze(self):
        findings = []
        log.debug("in references analyze")
        if self.cname_findings_direct:
            findings.extend(self._convert_findings(self.cname_findings_direct))
        return findings

    async def cleanup(self):
        if self.target_httpmanager:
            await self.target_httpmanager.close()
            log.debug("HTTP Manager cleaned up successfully.")
