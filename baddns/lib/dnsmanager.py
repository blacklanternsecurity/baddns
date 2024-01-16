import re
import logging
import dns.asyncresolver

log = logging.getLogger(__name__)


class DNSManager:
    dns_record_types = ["A", "AAAA", "MX", "CNAME", "NS", "SOA", "TXT", "NSEC"]

    _dns_name_regex = r"(?:\w(?:[\w-]{0,100}\w)?\.)+[^\W_]{1,63}"
    dns_name_regex = re.compile(_dns_name_regex, re.I)

    def __init__(self, target, dns_client=None, custom_nameservers=None):
        if not dns_client:
            self.dns_client = dns.asyncresolver.Resolver()
        else:
            self.dns_client = dns_client

        if custom_nameservers:
            self.dns_client.nameservers = custom_nameservers

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

    # These were stolen from BBOT. Thanks TheTechromancer for saving me from hours of suffering.
    @staticmethod
    def _clean_dns_record(record):
        if not isinstance(record, str):
            record = str(record.to_text())
        return str(record).rstrip(".").lower()

    def process_answer(self, answer, rdatatype):
        results = set()

        if answer == None:
            return []

        for record in answer:
            """
            Extract whatever hostnames/IPs a DNS records points to
            """

            rdtype = str(record.rdtype.name).upper()
            if rdtype in ("A", "AAAA", "NS", "CNAME", "PTR"):
                results.add(self._clean_dns_record(record))
            elif rdtype == "SOA":
                results.add(self._clean_dns_record(record.mname))
            elif rdtype == "MX":
                results.add(self._clean_dns_record(record.exchange))
            elif rdtype == "SRV":
                results.add(self._clean_dns_record(record.target))
            elif rdtype == "TXT":
                for s in record.strings:
                    s = s.decode()
                    results.add(s)
            elif rdtype == "NSEC":
                results.add(self._clean_dns_record(record.next))
            else:
                log.warning(f'Unknown DNS record type "{rdtype}"')
        return list(results)

    async def do_resolve(self, target, rdatatype):
        try:
            r = self.process_answer(await self.dns_client.resolve(target, rdatatype), rdatatype)
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
            log.debug(f"encountered error with dns_client.resolve(): {e}")
            self.answers["NoAnswer"] = True
            return
        except dns.resolver.NXDOMAIN:
            self.answers["NXDOMAIN"] = True
            return
        except dns.resolver.LifetimeTimeout as e:
            log.debug(f"Dns Timeout: {e}")
            return
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
                        r = self.process_answer(await self.dns_client.resolve(target, "CNAME"), "CNAME")
                        if len(r) == 0:
                            break
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
                        log.debug(f"Error resolving cname chain: {e}")
                        break
                return cname_chain
            return r

    async def dispatchDNS(self, omit_types=[]):
        log.debug(f"attempting to resolve {self.target}")
        log.debug(f"dispatching DNS with the following nameservers: {' '.join(self.dns_client.nameservers)}")
        for rdatatype in self.dns_record_types:
            if rdatatype in omit_types:
                continue
            try:
                self.answers[rdatatype] = await self.do_resolve(self.target, rdatatype)
            except dns.resolver.LifetimeTimeout:
                log.debug(f"Got LifetimeTimeout for rdatatype [{rdatatype}] for target [{self.target}]")
                self.answers[rdatatype] = None
