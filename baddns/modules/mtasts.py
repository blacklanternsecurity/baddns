import httpx
import logging
import fnmatch

from baddns.base import BadDNS_base
from baddns.lib.dnsmanager import DNSManager
from baddns.lib.whoismanager import WhoisManager
from baddns.lib.findings import Finding
from baddns.modules.cname import BadDNS_cname

log = logging.getLogger(__name__)


class BadDNS_mtasts(BadDNS_base):
    name = "MTA-STS"
    description = "Check for MTA-STS misconfigurations and dangling mta-sts subdomains"

    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)
        self.target = target

        self.target_dnsmanager = DNSManager(
            f"_mta-sts.{target}", dns_client=self.dns_client, custom_nameservers=self.custom_nameservers
        )
        self.mx_dnsmanager = DNSManager(target, dns_client=self.dns_client, custom_nameservers=self.custom_nameservers)

        self.sts_id = None
        self.cname_findings_direct = []
        self.cname_findings = []
        self.policy = None
        self.policy_error = None
        self.mx_whois_results = {}
        self.mta_sts_host = f"mta-sts.{target}"

        http_client_class = self.http_client_class or httpx.AsyncClient
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
        }
        self._policy_client = http_client_class(timeout=5, verify=False, headers=headers)

    async def _dispatch(self):
        # Step 1: Check for _mta-sts TXT record
        await self.target_dnsmanager.dispatchDNS(omit_types=["A", "AAAA", "CNAME", "NS", "SOA", "MX", "NSEC"])
        if self.target_dnsmanager.answers["TXT"] is None:
            log.debug("No _mta-sts TXT record found, aborting")
            return False

        # Parse for v=STSv1
        found_sts = False
        for txt_record in self.target_dnsmanager.answers["TXT"]:
            if "v=STSv1" in txt_record:
                found_sts = True
                # Extract id
                for part in txt_record.replace(" ", "").split(";"):
                    if part.startswith("id="):
                        self.sts_id = part[3:]
                break

        if not found_sts:
            log.debug("No v=STSv1 TXT record found, aborting")
            return False

        self.infomsg(f"Found MTA-STS TXT record for {self.target} (id={self.sts_id})")

        # Step 2: Delegate mta-sts.<target> to CNAME module (both direct and non-direct mode)
        cname_instance_direct = BadDNS_cname(
            self.mta_sts_host,
            custom_nameservers=self.custom_nameservers,
            signatures=self.signatures,
            direct_mode=True,
            parent_class="mtasts",
            http_client_class=self.http_client_class,
            dns_client=self.dns_client,
        )
        if await cname_instance_direct.dispatch():
            direct_results = cname_instance_direct.analyze()
            if direct_results:
                self.cname_findings_direct.append(
                    {
                        "finding": direct_results,
                        "description": f"Dangling mta-sts subdomain [{self.mta_sts_host}]",
                        "trigger": self.target,
                    }
                )
        await cname_instance_direct.cleanup()

        cname_instance = BadDNS_cname(
            self.mta_sts_host,
            custom_nameservers=self.custom_nameservers,
            signatures=self.signatures,
            direct_mode=False,
            parent_class="mtasts",
            http_client_class=self.http_client_class,
            dns_client=self.dns_client,
        )
        if await cname_instance.dispatch():
            cname_results = cname_instance.analyze()
            if cname_results:
                self.cname_findings.append(
                    {
                        "finding": cname_results,
                        "description": f"Dangling mta-sts subdomain [{self.mta_sts_host}]",
                        "trigger": self.target,
                    }
                )
        await cname_instance.cleanup()

        # Step 3: Fetch policy file
        policy_url = f"https://{self.mta_sts_host}/.well-known/mta-sts.txt"
        try:
            response = await self._policy_client.get(policy_url, follow_redirects=True)
            if response.status_code == 200:
                self.policy = self._parse_policy(response.text)
                log.debug(f"Parsed MTA-STS policy: {self.policy}")
            else:
                self.policy_error = f"HTTP {response.status_code}"
                log.debug(f"Policy fetch returned {response.status_code}")
        except Exception as e:
            self.policy_error = str(e)
            log.debug(f"Policy fetch failed: {e}")

        # Step 4: Query actual MX records
        await self.mx_dnsmanager.dispatchDNS(omit_types=["A", "AAAA", "CNAME", "NS", "SOA", "TXT", "NSEC"])

        # Step 5: WHOIS check on non-wildcard mx domains in policy
        if self.policy and self.policy.get("mx"):
            for mx_entry in self.policy["mx"]:
                if mx_entry.startswith("*."):
                    continue
                whois_mgr = WhoisManager(mx_entry)
                await whois_mgr.dispatchWHOIS()
                self.mx_whois_results[mx_entry] = whois_mgr

        return True

    @staticmethod
    def _parse_policy(text):
        policy = {"version": None, "mode": None, "max_age": None, "mx": []}
        for line in text.strip().splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key == "version":
                policy["version"] = value
            elif key == "mode":
                policy["mode"] = value
            elif key == "max_age":
                policy["max_age"] = value
            elif key == "mx":
                policy["mx"].append(value)
        return policy

    def _mx_matches(self, policy_mx_pattern, actual_mx):
        """Check if an actual MX hostname matches a policy mx pattern (supports wildcards)."""
        return fnmatch.fnmatch(actual_mx.lower(), policy_mx_pattern.lower())

    def _convert_cname_findings(self, finding_sets):
        converted = []
        for finding_set in finding_sets:
            for finding in finding_set["finding"]:
                finding_dict = finding.to_dict()
                log.debug(f"Found finding during cname check for mta-sts host: {finding_dict['target']}")
                converted.append(
                    Finding(
                        {
                            "target": self.target,
                            "description": f"{finding_set['description']}. Original Event: [{finding_dict['description']}]",
                            "confidence": finding_dict["confidence"],
                            "severity": "HIGH",
                            "signature": finding_dict["signature"],
                            "indicator": finding_dict["indicator"],
                            "trigger": finding_set["trigger"],
                            "module": type(self),
                        }
                    )
                )
        return converted

    def analyze(self):
        findings = []

        # Finding 1: Dangling mta-sts subdomain via CNAME delegation
        if self.cname_findings_direct:
            findings.extend(self._convert_cname_findings(self.cname_findings_direct))
        if self.cname_findings:
            findings.extend(self._convert_cname_findings(self.cname_findings))

        # Finding 2: Orphaned TXT record with unreachable policy
        if self.policy_error and not self.cname_findings_direct and not self.cname_findings:
            findings.append(
                Finding(
                    {
                        "target": self.target,
                        "description": f"Orphaned MTA-STS TXT record: _mta-sts.{self.target} exists but policy is unreachable ({self.policy_error})",
                        "confidence": "MODERATE",
                        "severity": "MEDIUM",
                        "signature": "N/A",
                        "indicator": "MTA-STS Policy Unreachable",
                        "trigger": f"_mta-sts.{self.target}",
                        "module": type(self),
                    }
                )
            )

        if self.policy:
            actual_mx = self.mx_dnsmanager.answers.get("MX") or []

            # Finding 3: Policy MX mismatch (only in enforce mode)
            if self.policy.get("mode") == "enforce" and actual_mx:
                unmatched = []
                for mx_host in actual_mx:
                    if not any(self._mx_matches(pattern, mx_host) for pattern in self.policy["mx"]):
                        unmatched.append(mx_host)
                if unmatched:
                    findings.append(
                        Finding(
                            {
                                "target": self.target,
                                "description": f"MTA-STS policy MX mismatch in enforce mode: actual MX records [{', '.join(unmatched)}] not covered by policy mx lines",
                                "confidence": "MODERATE",
                                "severity": "MEDIUM",
                                "signature": "N/A",
                                "indicator": "MTA-STS MX Mismatch",
                                "trigger": f"_mta-sts.{self.target}",
                                "module": type(self),
                            }
                        )
                    )

            # Finding 4: Dangling domains in policy mx lines (WHOIS)
            for mx_entry, whois_mgr in self.mx_whois_results.items():
                if whois_mgr.whois_result:
                    for whois_finding in whois_mgr.analyzeWHOIS():
                        findings.append(
                            Finding(
                                {
                                    "target": self.target,
                                    "description": f"MTA-STS policy mx domain {whois_finding}: {mx_entry}",
                                    "confidence": "CONFIRMED",
                                    "severity": "MEDIUM",
                                    "signature": "N/A",
                                    "indicator": "Whois Data",
                                    "trigger": mx_entry,
                                    "module": type(self),
                                }
                            )
                        )

        return findings

    async def cleanup(self):
        if self._policy_client:
            await self._policy_client.aclose()
            log.debug("MTA-STS policy client closed successfully.")
