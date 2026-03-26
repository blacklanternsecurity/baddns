import re
import logging
import asyncio

from blastdns import Client, DNSError, get_system_resolvers, BlastDNSError, ResolverError

log = logging.getLogger(__name__)


class DNSManager:
    dns_record_types = ["A", "AAAA", "MX", "CNAME", "NS", "SOA", "TXT", "NSEC"]

    _dns_name_regex = r"(?:\w(?:[\w-]{0,100}\w)?\.)+[^\W_]{1,63}"
    dns_name_regex = re.compile(_dns_name_regex, re.I)

    def __init__(self, target, dns_client=None, custom_nameservers=None):
        if custom_nameservers:
            # Create a new client with custom nameservers, since blastdns
            # clients are configured with resolvers at construction time
            self.dns_client = Client(custom_nameservers)
        elif dns_client:
            self.dns_client = dns_client
        else:
            self.dns_client = Client(get_system_resolvers())

        self.tld_nameservers = None

        self.target = target
        self.reset_answers()
        self.ips = []

    def reset_answers(self):
        self.answers = {key: None for key in self.dns_record_types}
        self.answers.update({"NoAnswer": False, "NXDOMAIN": False})

    @staticmethod
    def get_ipv4(a_records):
        ipv4 = []
        for answer in a_records:
            log.debug(f"Found IPV4 address: {answer}")
            ipv4.append(str(answer))
        return ipv4

    @staticmethod
    def get_ipv6(aaaa_records):
        ipv6 = []
        for answer in aaaa_records:
            log.debug(f"Found IPV6 address: {answer}")
            ipv6.append(str(answer))
        return ipv6

    @staticmethod
    def _clean_dns_record(record):
        return str(record).rstrip(".").lower()

    def process_answer(self, result, rdatatype):
        """Extract string answers from a blastdns DNSResult.

        blastdns rdata formats:
          - A/AAAA/CNAME/NS/PTR: {"A": "1.2.3.4"} (simple string)
          - MX: {"MX": {"preference": 10, "exchange": "mail.example.com."}}
          - TXT: {"TXT": {"txt_data": [[byte_values...]]}}
          - SOA: {"SOA": {"mname": "ns1.", "rname": "admin.", ...}}
          - SRV: {"SRV": {"priority": 0, "weight": 100, "port": 389, "target": "host."}}
          - NSEC: {"NSEC": {"next_domain_name": "next.", "type_bit_maps": [...]}}
        """
        if result is None:
            return []

        results = set()
        for record in result.response.answers:
            for rdtype, value in record.rdata.items():
                rdtype = rdtype.upper()
                if rdtype in ("A", "AAAA", "NS", "CNAME", "PTR"):
                    cleaned = self._clean_dns_record(str(value))
                    if cleaned:
                        results.add(cleaned)
                elif rdtype == "SOA":
                    if isinstance(value, dict):
                        mname = value.get("mname", "")
                        cleaned = self._clean_dns_record(str(mname))
                    else:
                        cleaned = self._clean_dns_record(str(value).split()[0])
                    if cleaned:
                        results.add(cleaned)
                elif rdtype == "MX":
                    if isinstance(value, dict):
                        exchange = value.get("exchange", "")
                        cleaned = self._clean_dns_record(str(exchange))
                    else:
                        cleaned = self._clean_dns_record(str(value).split()[-1])
                    if cleaned:
                        results.add(cleaned)
                elif rdtype == "SRV":
                    if isinstance(value, dict):
                        target = value.get("target", "")
                        cleaned = self._clean_dns_record(str(target))
                    else:
                        cleaned = self._clean_dns_record(str(value).split()[-1])
                    if cleaned:
                        results.add(cleaned)
                elif rdtype == "TXT":
                    if isinstance(value, dict):
                        # blastdns format: {"txt_data": [[byte_values...]]}
                        txt_data = value.get("txt_data", [])
                        parts = []
                        for part in txt_data:
                            if isinstance(part, list):
                                parts.append(bytes(part).decode("utf-8", errors="replace"))
                            else:
                                parts.append(str(part))
                        s = "".join(parts)
                    else:
                        s = str(value).strip('"').replace('" "', "")
                    results.add(s)
                elif rdtype == "NSEC":
                    if isinstance(value, dict):
                        next_domain = value.get("next_domain_name", "")
                        cleaned = self._clean_dns_record(str(next_domain))
                    else:
                        cleaned = self._clean_dns_record(str(value).split()[0])
                    if cleaned:
                        results.add(cleaned)
                elif rdtype == "UNKNOWN":
                    # Handle unsupported record types passed through as Unknown
                    if isinstance(value, dict):
                        raw = value.get("rdata", {})
                        raw_bytes = raw.get("anything", [])
                        if raw_bytes and isinstance(raw_bytes, list):
                            decoded = bytes(raw_bytes).decode("utf-8", errors="replace")
                            cleaned = self._clean_dns_record(decoded.split()[0])
                            if cleaned:
                                results.add(cleaned)
                else:
                    log.debug(f'Unknown DNS record type "{rdtype}"')
        return list(results)

    async def do_resolve(self, target, rdatatype):
        try:
            result = await self.dns_client.resolve_full(target, rdatatype)
        except ResolverError as e:
            log.debug(f"DNS resolver error for {target} {rdatatype}: {e}")
            self.answers["NoAnswer"] = True
            return
        except BlastDNSError as e:
            log.warning(f"DNS error for {target} {rdatatype}: {e}")
            return

        # Check for error responses
        if isinstance(result, DNSError):
            log.debug(f"DNS error: {result.error}")
            self.answers["NoAnswer"] = True
            return

        # Check response code for NXDOMAIN
        response_code = result.response.header.response_code
        if response_code == "NXDomain":
            self.answers["NXDOMAIN"] = True
            return

        # No answers means NoAnswer
        if not result.response.answers:
            self.answers["NoAnswer"] = True
            return

        r = self.process_answer(result, rdatatype)
        if r and len(r) > 0:
            if rdatatype == "A":
                self.ips.extend(self.get_ipv4(r))
            elif rdatatype == "AAAA":
                self.ips.extend(self.get_ipv6(r))

            elif rdatatype == "CNAME":
                cname_chain = []

                while 1:
                    result_cname = r[0]
                    cname_chain.append(result_cname)
                    target = result_cname

                    try:
                        chain_result = await self.dns_client.resolve_full(target, "CNAME")
                        if isinstance(chain_result, DNSError):
                            break
                        if chain_result.response.header.response_code != "NoError":
                            break
                        if not chain_result.response.answers:
                            break
                        r = self.process_answer(chain_result, "CNAME")
                        if len(r) == 0:
                            break
                    except BlastDNSError as e:
                        log.debug(f"Error resolving cname chain: {e}")
                        break
                return cname_chain
            return r

    async def dispatchDNS(self, omit_types=[]):
        log.debug(f"attempting to resolve {self.target}")
        log.debug(f"dispatching DNS with resolvers: {self.dns_client.resolvers}")

        tasks = []
        for rdatatype in self.dns_record_types:
            if rdatatype in omit_types:
                continue
            # Capture the current rdatatype for each task
            task = asyncio.create_task(self.do_resolve(self.target, rdatatype))
            tasks.append((task, rdatatype))  # Store the task along with its rdatatype

        for task, rdatatype in tasks:  # Unpack the task and its corresponding rdatatype
            self.answers[rdatatype] = await task
