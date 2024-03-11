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

    def parse_body(self, body):
        results = []
        for match in self.regex_jssrc.finditer(body):
            js_url = match.group(1)
            parsed_url = urlparse(js_url)
            js_domain = parsed_url.netloc
            results.append(
                {
                    "url": js_url,
                    "domain": js_domain,
                    "description": "Hijackable reference, JS Include",
                    "trigger": f"Javascript Source: [{js_url}]",
                }
            )

        for match in self.regex_csssrc.finditer(body):
            css_url = match.group(1)
            parsed_url = urlparse(css_url)
            css_domain = parsed_url.netloc
            results.append(
                {
                    "url": css_url,
                    "domain": css_domain,
                    "description": "Hijackable reference, CSS Include",
                    "trigger": f"CSS Source: [{css_url}]",
                }
            )
        return results

    async def dispatch(self):
        log.debug("in references dispatch")
        await self.target_httpmanager.dispatchHttp()
        log.debug("HTTP dispatch complete")

        live_results = []

        for protocol in ["http", "https"]:
            result = getattr(self.target_httpmanager, f"{protocol}_denyredirects_results")
            if result:
                log.debug(f"Found live host at {result.url}")
                live_results.append(result)

        self.cname_findings_direct = []
        self.cname_findings = []

        for r in live_results:
            parsed_results = self.parse_body(r.text)
            if parsed_results:
                for pr in parsed_results:
                    if pr["domain"] == self.target:
                        log.debug(f"Found domain matches target ({self.target}), ignoring")
                        continue
                    log.debug(f"Initializing cname instance for target {pr['domain']}")

                    cname_instance_direct = BadDNS_cname(
                        pr["domain"],
                        custom_nameservers=self.custom_nameservers,
                        signatures=self.signatures,
                        direct_mode=True,
                        parent_class="references",
                        http_client_class=self.http_client_class,
                        dns_client=self.dns_client,
                    )
                    if await cname_instance_direct.dispatch():
                        self.cname_findings_direct.append(
                            {
                                "finding": cname_instance_direct.analyze(),
                                "description": pr["description"],
                                "trigger": pr["trigger"],
                            }
                        )

                    cname_instance = BadDNS_cname(
                        pr["domain"],
                        custom_nameservers=self.custom_nameservers,
                        signatures=self.signatures,
                        direct_mode=False,
                        parent_class="references",
                        http_client_class=self.http_client_class,
                        dns_client=self.dns_client,
                    )
                    if await cname_instance.dispatch():
                        self.cname_findings.append(
                            {
                                "finding": cname_instance.analyze(),
                                "description": pr["description"],
                                "trigger": pr["trigger"],
                            }
                        )
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
                            "trigger": finding_set["trigger"],
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
        if self.cname_findings:
            findings.extend(self._convert_findings(self.cname_findings))
        return findings
