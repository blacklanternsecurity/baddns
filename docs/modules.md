## cname

The `cname` modules check for "Dangling" CNAME records, and then interrogates them for takeover opportunities. 

A dangling DNS record just refers to a record which points to a resource that doesn't exist anymore. In the context of a subdomain takeover, this can mean a couple different things. It might mean pointing to an \*.azurewebsites.net instance (for example) that isn't registered anymore, and results in an NXDOMAIN result. That means someone else can register it, and have the dangling CNAME record point to their resource. It could also point to a service (say, wordpress for example) that resolves, but results in a particular error message or status code that indicates the particular subdomain is available.

All of the specific knowledge for each of these services is contained within [signatures](signatures.md). When a dangling CNAME is discovered, it will be checked against every signature for a match. If a match is found, it is considered a `VULNERABILITY`. If not, it might still be interesting (it could be an undiscovered new type of takeover!) and will be noted (If using BadDNS via the [BBOT](https://github.com/blacklanternsecurity/bbot/) module, these will be emitted as a `FINDING` for generic dangling record). 

Since many takeover detections rely on strings within HTTP content, BadDNS makes HTTP requests to it's targets in addition to the DNS requests it makes. 

WHOIS requests are also made, which are used to evaluate the expiration date of the target of the CNAME's base domain. It's not just about subdomains! If you can takeover a base domain, by definition you get **every** subdomain for that domain. 


## ns

NS records can be dangling too. Like with CNAME records, a signature is required to determine if the dangling record is exploitable. Also like with CNAME records, generic dangling NS records are reported in case they reveal a new type of takeover nobody has investigated yet. 

To identify a "Dangling" NS record, we look at NS records that we find without a corresponding SOA record. As noted in the [research notes](research.md), this can be a little tricky because DNS servers seem to have some differences in this behavior in this area. Some of them will **lie** to you about an NS record it finds, if it can't find an SOA record, effectively masking the danling NS records. To deal with this, the `ns` module mimicks the behavior of an actual DNS server making a recursive looking, starting a the TLD (top-level domain). 

If it finds any dangling NS records, they are checked against every `ns` signature for a match.


## nsec

NSEC walking refers to a method used by attackers to enumerate the contents of a DNS zone when DNSSEC (DNS Security Extensions) is implemented. DNSSEC was designed to add an extra layer of security to the DNS by validating the authenticity of the responses. It uses two record types for this purpose: NSEC (Next Secure Record) and NSEC3. These records provide proof of non-existence of a DNS record, helping to prevent common attacks like cache poisoning.

However, NSEC records inadvertently introduce a vulnerability. An NSEC record not only indicates that a specific DNS record does not exist but also reveals the next valid domain name in the DNS zone. By continuously querying for non-existent records, an attacker can use the responses to gradually map the entire set of domain names in a zone, a technique known as NSEC walking. This process can uncover subdomains and other DNS entries that might not be intended for public knowledge.

The NSEC modules looks for instances where NSEC records are present, and then attempts to actually "walk" the records, and then reports all of the domains it finds in the process.

## references

What happens if a website is pointing to an external source for it's Javascript or CSS, and that external source can be taken over? The best cross-site scripting you could ever ask for! The references module does just that, wrapping the `cname` module behind the scenes and sending any CSS/JS domains found in the target's HTML content. If a match is found, it's emitted with the added context of the page it was found in.

## txt

TXT records are used for all kinds things. Often, they are used for verifying ownership of a domain. A service may request a specific TXT record be set, which can only be done by the domain owner, thereby proving ownership. But beyond that, who knows what they are being used for! Probably all kinds of wacky custom things. What happens when a txt record just happens to contain a domain/subdomain that just happens to be "take-over-able?". Well, we don't know. This type of detection is the least likely to be exploitable but if it is, it could be very interesting. If you get a detection here, it's worth doing the takeover and just spinning up a server and seeing what requests get sent to it.

Behind the scenes, when a domain is found in a TXT record, the `txt` module actually sends the domain/subdomain to the `cname` module where it gets processed just like any other subdomain. If there's a hit, its emitted with the added context of the TXT record it was found in. 

## zonetransfer

Zone transfers are a legitimate function used by DNS servers to synchronize DNS record information between a primary DNS server and its secondary servers. This synchronization ensures that all servers have an up-to-date copy of the DNS records, which are crucial for routing internet traffic to the correct locations.

While essential for DNS operation, zone transfers can pose significant security risks if not properly secured. An unrestricted zone transfer can expose all DNS records of a domain to unauthorized parties. Although rare, when they do occur they typically yield every domain for the organization, which can be a gold mine for an attacker trying to perform recon against a target.

The zonetransfer module will interrogate the name server(s) that are authoritative for the target domain and attempt a zone transfer. If successful, it will also harvest all of the available records and present them within the result.