from baddns.base import BadDNS_base
from baddns.lib.findings import Finding
from baddns.lib.dnsmanager import DNSManager

import logging
import dns.zone
import dns.query
import asyncio

log = logging.getLogger(__name__)


class BadDNS_zonetransfer(BadDNS_base):
    name = "zonetransfer"
    description = "Attempt a DNS zone transfer"
    zone_records = []
    zone_nameservers = []

    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)
        self.target_dnsmanager = DNSManager(target, dns_client=self.dns_client)

    def parse_zone(self, zone):
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                record_type = dns.rdatatype.to_text(rdataset.rdtype)
                for rdata in rdataset:
                    raw_name = name.to_text()
                    if str(raw_name) == "@":
                        processed_name = self.target_dnsmanager.target
                    else:
                        processed_name = f"{raw_name}.{self.target_dnsmanager.target}"
                    record = (processed_name, record_type, rdata.to_text())
                    if record[0] not in self.zone_records:
                        self.zone_records.append(record[0])

    async def zone_transfer(self, nameserver, domain):
        ns_ips = await self.target_dnsmanager.do_resolve(nameserver, "A")
        ns_ip = ns_ips[0]
        try:
            zone = await asyncio.to_thread(dns.zone.from_xfr, dns.query.xfr(ns_ip, domain, timeout=10))

        except dns.exception.Timeout:
            log.debug("TimeoutError attempting zone transfer")
            return False
        except ConnectionResetError:
            log.debug("ConnectionResetError attempting zone transfer")
            return False
        except dns.xfr.TransferError as e:
            log.debug(f"{nameserver} ({ns_ip}): {e}")
            return False
        self.zone_nameservers.append(nameserver)
        self.parse_zone(zone)
        return True

    async def dispatch(self):
        zone_transfer_detected = False
        await self.target_dnsmanager.dispatchDNS(omit_types=["A", "MX", "AAAA", "CNAME", "SOA", "TXT", "NSEC"])
        if self.target_dnsmanager.answers["NS"]:
            for ns in self.target_dnsmanager.answers["NS"]:
                log.debug(f"Attempting Zone Transfer against NS [{ns}] for target [{self.target_dnsmanager.target}]")
                r = await self.zone_transfer(ns, self.target_dnsmanager.target)
                if r:
                    zone_transfer_detected = True
                    log.info(
                        f"Successful Zone Transfer against NS [{ns}] for target [{self.target_dnsmanager.target}]"
                    )
        return zone_transfer_detected

    def analyze(self):
        findings = []
        if self.zone_records:
            findings.append(
                Finding(
                    {
                        "target": self.target_dnsmanager.target,
                        "description": "Successful Zone Transfer",
                        "confidence": "CONFIRMED",
                        "signature": "N/A",
                        "indicator": "Successful XFR Request",
                        "trigger": self.zone_nameservers,
                        "module": type(self),
                        "found_domains": self.zone_records,
                    }
                )
            )
        return findings
