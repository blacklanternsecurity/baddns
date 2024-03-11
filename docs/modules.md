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