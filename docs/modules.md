## cname

The `cname` modules check for "Dangling" CNAME records, and then interrogates them for takeover opportunities. 

A dangling DNS record refers to a record which points to a resource that doesn't exist anymore. In the context of a subdomain takeover, this can manifest in several ways. For instance, consider a record pointing to an \*.azurewebsites.net instance (for example) that isn't registered anymore, and results in an NXDOMAIN result. This situation allows someone else to register the same instance with Azure and redirect the dangling CNAME record to their resource.  It could also point to a service (such as WordPress) that resolves but results in a particular error message or status code indicating that the subdomain is available for use within the service.

All of the specific knowledge for each of these services is contained within [signatures](signatures.md). When a dangling CNAME is discovered, it will be checked against every signature for a match. If a match is found, it is considered a `VULNERABILITY`. If not, it might still be interesting (it could be an undiscovered new type of takeover) and will be reported accordingly. When using BadDNS via the [BBOT](https://github.com/blacklanternsecurity/bbot/) module, these instances are reported as a `FINDING` for a generic dangling record.

Since many takeover detections depend on strings within HTTP content, BadDNS performs HTTP requests to its targets, in addition to DNS queries.

WHOIS requests are also made, which are used to determine the expiration date of the CNAME's base domain target. The focus of BadDNS isn't solely on subdomains; taking over a base domain inherently grants control over all its subdomains.

## ns

NS records can also be subject to dangling issues, similar to CNAME records. A signature is necessary to determine if the dangling NS record is exploitable. Additionally, generic dangling NS records are reported, as they might reveal a new type of takeover that has not yet been investigated.

To identify a "Dangling" NS record, we examine NS records that exist without a corresponding SOA (Start of Authority) record. As noted in the [research notes](research.md), this process can be challenging due to variations in DNS server behavior. Some of them will **lie** to you about an NS record they find if they can't find an SOA record, effectively concealing the dangling NS records. To deal with this, the `ns` module mimicks the behavior of an actual DNS server making a recursive lookups, starting a the TLD (top-level domain). 

If it finds any dangling NS records, they are checked against every `ns` signature for a match.


## nsec

NSEC walking refers to a method used by attackers to enumerate the contents of a DNS zone when DNSSEC (DNS Security Extensions) is implemented. DNSSEC was designed to add an extra layer of security to the DNS by validating the authenticity of the responses. It uses two record types for this purpose: NSEC (Next Secure Record) and NSEC3. These records provide proof of non-existence of a DNS record, helping to prevent common attacks like cache poisoning.

However, NSEC records inadvertently introduce a vulnerability. An NSEC record not only indicates that a specific DNS record does not exist but also reveals the next valid domain name in the DNS zone. By continuously querying for non-existent records, an attacker can use the responses to gradually map the entire set of domain names in a zone, a technique known as NSEC walking. This process can uncover subdomains and other DNS entries that might not be intended for public knowledge.

The NSEC module looks for instances where NSEC records are present, and then attempts to actually "walk" the records, and then report all of the domains it finds in the process.

## references

What happens if a website is pointing to an external source for it's Javascript or CSS, and that external source can be taken over? The best cross-site scripting you could ever ask for. The references module does just that, wrapping the `cname` module behind the scenes and sending any CSS/JS domains found in the target's HTML content for analysis. If a match is found, it's emitted with the added context of the page it was found in.

## txt

TXT records in DNS serve a variety of purposes, one common use being domain ownership verification. A service may require setting a specific TXT record, a task achievable only by the domain owner, thereby confirming ownership. However, the utilization of TXT records extends far beyond this. They are often employed for a myriad of custom, sometimes unconventional, purposes.

What happens when a TXT record just happens to contain a domain/subdomain that just happens to be vulnerable to a takeover?. Who knows. This type of detection is the least likely to be exploitable - but if it is, it could be very interesting. If you get a detection here, it's worth doing the takeover and just spinning up a server and seeing what requests get sent to it.

Behind the scenes, when a domain is found in a TXT record, the `txt` module actually sends the domain/subdomain to the `cname` module where it gets processed just like any other subdomain. If there's a hit, its emitted with the added context of the TXT record it was found in. 

## mx

Taking over a dangling MX record can have significant consequences. If an organization has multiple MX records and some of them are still functional, they may not notice that there is a dangling record present. An attacker who is able to gain control of a domain the dangling record is pointing to can start receiving a portion of an organization's email. Although the impact of control of an email server heavily depends on the priority settings for the various mail servers (emails may only go to lower priority servers if the higher priority servers go down), it can have a significant impact. In addition to the partial loss of email functionality, credentials or other sensitive information could be captured if they are shared in the intercepted emails.

A crafty attacker might even resend messages they siphon off, so the organization never notices a problem, and then silently gain access to a portion of their emails indefinitely.

## zonetransfer

Zone transfers are a legitimate function used by DNS servers to synchronize DNS record information between a primary DNS server and its secondary servers. This synchronization ensures that all servers have an up-to-date copy of the DNS records, which are crucial for routing internet traffic to the correct locations.

While essential for DNS operation, zone transfers can pose significant security risks if not properly secured. An unrestricted zone transfer can expose all DNS records of a domain to unauthorized parties. Although rare, when they do occur they typically yield every domain for the organization, which can be a gold mine for an attacker trying to perform recon against a target.

The `zonetransfer` module will interrogate the name server(s) that are authoritative for the target domain and attempt a zone transfer. If successful, it will also harvest all of the available records and present them within the result.

## dmarc

DMARC (Domain-based Message Authentication, Reporting, and Conformance) is a DNS-based email authentication protocol that helps protect domains from being used in email spoofing attacks. A DMARC record is published as a TXT record at `_dmarc.<domain>` and specifies a policy (`none`, `quarantine`, or `reject`) that tells receiving mail servers how to handle messages that fail authentication checks.

The `dmarc` module queries for DMARC records and checks for several misconfigurations:

- **Missing DMARC record** — No `_dmarc` TXT record exists at all, leaving the domain with no protection against email spoofing.
- **Policy set to `none`** — A `p=none` policy means spoofed emails will still be delivered, offering monitoring but no enforcement.
- **Weak subdomain policy** — The `sp=none` tag or an inherited `p=none` from the organizational domain means subdomains can be spoofed even if the parent domain has a stricter policy.
- **Partial enforcement** — A `pct` value less than 100 means the policy is only applied to a fraction of messages.
- **No aggregate reporting** — Missing `rua` tag means the domain owner receives no reports about authentication failures.

For subdomains, the module implements the RFC 7489 two-step lookup: it first checks `_dmarc.<subdomain>`, and if no record is found, falls back to the organizational domain's DMARC record.

## mta-sts

MTA-STS (Mail Transfer Agent Strict Transport Security) is a mechanism that allows mail service providers to declare their ability to receive TLS-secured connections and to specify whether sending SMTP servers should refuse to deliver to MX hosts that do not offer TLS. It works via a TXT record at `_mta-sts.<domain>` and a policy file hosted at `https://mta-sts.<domain>/.well-known/mta-sts.txt`.

The `mta-sts` module checks for several issues related to MTA-STS configuration:

- **Dangling mta-sts subdomain** — If `mta-sts.<domain>` has a dangling CNAME, an attacker could take over the subdomain and serve a malicious MTA-STS policy, potentially redirecting email to attacker-controlled mail servers. The module delegates to the `cname` module to check the `mta-sts` subdomain for takeover opportunities.
- **Orphaned TXT record** — The `_mta-sts` TXT record exists but the policy file is unreachable, indicating a stale or misconfigured deployment.
- **Policy MX mismatch** — In `enforce` mode, if actual MX records don't match the policy's `mx` lines, legitimate email delivery may be disrupted.
- **Dangling MX domains in policy** — WHOIS checks on domains listed in the policy's `mx` lines can reveal expired or available domains that could be registered by an attacker.

## wildcard

A wildcard DNS record (e.g., `*.example.com`) causes all subdomains to resolve to the same target. While this is sometimes intentional, it can have serious security implications if the wildcard points to a CNAME that is vulnerable to takeover.

The `wildcard` module probes for wildcard DNS records by querying a random subdomain of the target's parent domain. If a wildcard CNAME is detected, the module delegates to the `cname` module to check whether the CNAME target is dangling or matches a known takeover signature.

A successful wildcard CNAME takeover is particularly severe because it affects **all** subdomains of the parent domain simultaneously, not just a single subdomain. This means a single dangling wildcard CNAME could expose thousands of subdomains to takeover at once.

## spf

SPF (Sender Policy Framework) is a DNS-based email authentication mechanism that specifies which mail servers are authorized to send email on behalf of a domain. An SPF record is published as a TXT record at the domain and contains a list of mechanisms (`include`, `a`, `mx`, `ip4`, `ip6`, etc.) and a default qualifier (`-all`, `~all`, `?all`, or `+all`) that determines how unauthorized senders are handled.

The `spf` module queries for SPF records and checks for several issues:

- **Missing SPF record** — No SPF TXT record exists, leaving the domain with no protection against email spoofing.
- **Multiple SPF records** — More than one SPF record causes a permanent error per RFC 7208, effectively breaking SPF entirely.
- **Permissive `+all`** — Explicitly authorizes any server to send email for the domain, rendering SPF useless.
- **Neutral `?all`** — Provides no protection against unauthorized senders.
- **DNS lookup limit exceeded** — SPF records that exceed the 10 DNS lookup limit per RFC 7208 cause a permanent error.
- **Hijackable include/redirect domains** — WHOIS checks on domains referenced in `include` and `redirect` mechanisms can reveal expired or available domains that could be registered by an attacker to authorize their own mail servers.

For subdomains, the module falls back to the organizational domain's SPF record if no direct SPF record is found, since SPF policy at the parent domain covers subdomains.