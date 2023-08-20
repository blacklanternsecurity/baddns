import dns.query
import dns.message
import dns.rdatatype
import dns.name
import dns.resolver
import logging

log = logging.getLogger(__name__)


class DnsWalk:
    root_servers = [
        "198.41.0.4",
        "199.9.14.201",
        "192.33.4.12",
        "199.7.91.13",
        "192.203.230.10",
        "192.5.5.241",
        "192.112.36.4",
        "198.97.190.53",
        "192.36.148.17",
        "192.58.128.30",
        "193.0.14.129",
        "199.7.83.42",
        "202.12.27.33",
    ]

    max_depth = 10

    def __init__(self, dns_manager):
        self.dns_manager = dns_manager

    async def a_resolve(self, nameserver):
        nameserver_ips = set()
        a_query_results = await self.dns_manager.do_resolve(nameserver, "A")
        if a_query_results:
            for result in a_query_results:
                nameserver_ips.add(result)
            return list(nameserver_ips)
        else:
            return None

    async def ns_trace(self, target):
        log.debug(f"Attempting to find NS records for {target}")
        nameserver_ips = self.root_servers[:]
        solved_nameservers = await self.ns_recursive_solve(nameserver_ips, target, depth=0)
        log.debug(f"Found the following name servers: {solved_nameservers}")
        return solved_nameservers

    async def ns_recursive_solve(self, nameserver_ips, target, depth=0):
        if depth > self.max_depth:
            log.error(f"Reached max depth {str(self.max_depth)} attempting to resolve NS records (infinite loop)")
            return []
        final_results = set()
        log.debug(
            f"Recursive instance: nameserver_ips [{' '.join(nameserver_ips)}] target [{target}] at depth {str(depth)}"
        )
        depth += 1
        next_nameservers = set()
        for nameserver_ip in nameserver_ips:
            log.debug(f"Asking nameserver [{nameserver_ip}] NS records on {target}")
            query_msg = dns.message.make_query(target, dns.rdatatype.NS)
            response_msg, used_tcp = await dns.asyncquery.udp_with_fallback(query_msg, nameserver_ip)
            if response_msg.authority:
                log.debug(f"Server [{nameserver_ip}] responded with authority section")
                for ns_rrset in response_msg.authority:
                    for rr in ns_rrset:
                        if rr.rdtype == dns.rdatatype.NS:
                            rr_domain = rr.target.to_text().rstrip(".")
                            log.debug(f"Received NS record for [{rr_domain}]")
                            rr_ips = await self.a_resolve(rr_domain)
                            if rr_ips:
                                log.debug(f"Resolved [{rr_domain}] to ip(s) [{' '.join(rr_ips)}]")
                                next_nameservers.update(rr_ips)
                            else:
                                log.debug(f"Could not resolve [{rr_domain}] to an IP!")

                            log.debug(f"Adding {rr_domain} to temp results list, pending deeper results")
                            final_results.add(rr_domain)
                # If we were provided an authority section but nothing resolved, report the last set - they could be dangling
                if not next_nameservers:
                    log.debug("None of the servers provded in the authority section resolved")
                    log.debug(f"Submitting [{' '.join(final_results)}] as final result")
                    return final_results

                # If we had an authority section, and at least one resolved, we need to recurse again
                log.debug("Resolvable authority results were found. Recursing deeper")
                recurse = await self.ns_recursive_solve(next_nameservers, target, depth=depth)

                # If we tried again and didn't get an answer, we might be pointing to a real NS server with no resullts - these could be dangling
                if recurse == []:
                    log.debug("Did not get any additional results from latest recursion.")
                    log.debug(f"Submitting [{' '.join(final_results)}] as final result")
                    return list(final_results)
                else:
                    # If we got results from recursing, we are finishing and are shooting the results back up to the top
                    log.debug("Results were returned from downstream recurse. Forwarding the results up the stack.")
                    return recurse
            else:
                log.debug("No Authority section was found. Checking for answers section...")
                # If there was no authority section, but there was an answer section, we can trust the results
                if response_msg.answer and len(response_msg.answer) > 0:
                    log.debug("Found answer section!")
                    for rrset in response_msg.answer:
                        for rr in rrset:
                            if rr.rdtype == dns.rdatatype.CNAME:
                                solved_cname = await self.dns_manager.do_resolve(rr.to_text().rstrip("."), "NS")
                                if solved_cname:
                                    log.critical(solved_cname)
                                    final_results.update(solved_cname)
                            elif rr.rdtype == dns.rdatatype.NS:
                                final_results.add(rr.target.to_text().rstrip("."))
                # if there was no authority section, and no answer section, we stop and report whatever the last set was, or and empty set (Probably just has no nameservers)
                else:
                    log.debug("There was no answer section (or authority section)")
            log.debug("Moving on to next nameserver at current recurse level")
        log.debug("Exhausted entire list of nameservers. Returning any results found.")
        return list(final_results)
