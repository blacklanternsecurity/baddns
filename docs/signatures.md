The signatures used by several BadDNS modules are ultimately sourced from two main projects:

* [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates). The nuclei templates pertaining to subdomain takeovers are automatically converted and imported into BadDNS
* [dnsReaper](https://github.com/punk-security/dnsReaper). Another excellent project devoted to discovering subdomain takeovers, whose signatures are imported and converted into BadDNS.

GitHub automation pipelines monitor these projects for any new signatures. If they are found, they are converted into BadDNS's format. Tests will be run against the converted signatures. If the tests pass and the signatures look good, they can be imported into BadDNS with one click by the maintainers.

BadDNS can also maintain it's own, unique, signatures when necessary.

Rather than contribute further to the fragmentation of DNS-based signatures by creating another set of them, BadDNS aims to utilize and support existing repositories of signatures.

Currently, the ultimate source of many of these signatures is the `https://github.com/EdOverflow/can-i-take-over-xyz` repository. The issues section of this repo has become a centralized discussion place for signatures. Many of these discussions are used to create signatures within Nuclei. Ultimately, these Nuclei signatures are converted and used within BadDNS.

We highly encourage contributions to the signatures on these projects and to the discussions on `can-i-take-over-xyz`, as ultimately these are fed into BadDNS and benefit the entire community.

## Signature Format

Signatures are YAML files in `baddns/signatures/`. Each signature has the following fields:

| Field | Description |
|---|---|
| `service_name` | Name of the service (e.g., `"Netlify"`, `"AWS Route53"`) |
| `source` | Origin of the signature: `dnsreaper`, `nucleitemplates`, or `self` |
| `mode` | Detection mode (see below) |
| `identifiers` | Patterns to match against DNS records |
| `matcher_rule` | HTTP response matching rules (required for `http` mode, must be `null` for DNS modes) |
| `negative_signature` | Optional. Set to `true` to mark a provider as not exploitable (default: `false`) |

### Modes

- **`http`** — Matches CNAME identifiers, then checks HTTP response body/headers against `matcher_rule`. Used by the CNAME module.
- **`dns_nxdomain`** — Matches CNAME identifiers where the CNAME target returns NXDOMAIN. Used by the CNAME module.
- **`dns_nosoa`** — Matches nameserver identifiers where NS records exist but no SOA is returned. Used by the NS module.

### Identifiers

```yaml
identifiers:
  cnames:            # CNAME patterns to match (used by http and dns_nxdomain modes)
  - type: word
    value: netlify.app
  not_cnames: []     # CNAME patterns that exclude a match
  ips: []            # IP addresses to match
  nameservers:       # Nameserver substrings to match (used by dns_nosoa mode)
  - awsdns
```

### Examples

HTTP mode (CNAME + response matching):

```yaml
identifiers:
  cnames:
  - type: word
    value: netlify.app
  ips: []
  nameservers: []
  not_cnames: []
matcher_rule:
  matchers:
  - condition: or
    part: body
    type: word
    words:
    - 'Not Found - Request ID:'
  matchers-condition: and
mode: http
service_name: Netlify
source: dnsreaper
```

DNS NS mode (dangling nameservers):

```yaml
identifiers:
  cnames: []
  ips: []
  nameservers:
  - awsdns
  not_cnames: []
matcher_rule: null
mode: dns_nosoa
service_name: AWS Route53
source: dnsreaper
```

## Negative Signatures

Negative signatures mark providers as **not exploitable**, suppressing generic low-confidence findings. When the NS module finds dangling NS records but no positive signature match, it checks negative signatures before falling back to a generic finding. If a negative signature matches, no finding is reported.

Positive signatures always take priority over negative ones.

To create a negative signature, add `negative_signature: true` to a standard signature file. By convention, name these files with a `negative_` prefix:

```yaml
identifiers:
  cnames: []
  ips: []
  nameservers:
  - ultradns.com
  - ultradns.net
  - ultradns.org
  - ultradns.biz
  not_cnames: []
matcher_rule: null
mode: dns_nosoa
service_name: UltraDNS
source: self
negative_signature: true
```
