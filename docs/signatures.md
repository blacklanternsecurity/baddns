The signatures used by several BadDNS modules are ultimately sourced from two main projects:

* [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates). The nuclei templates pertaining to subdomain takeovers are automatically converted and imported into BadDNS
* [dnsReaper](https://github.com/punk-security/dnsReaper). Another excellent project devoted to discovering subdomain takeovers, whose signatures are imported and converted into BadDNS.

GitHub automation pipelines monitor these projects for any new signatures. If they are found, they are converted into BadDNS's format. Tests will be run against the converted signatures. If the tests pass and the signatures look good, they can be imported into BadDNS with one click by the maintainers.

BadDNS can also maintain it's own, unique, signatures when necessary.

Rather than contribute further to the fragmentation of DNS-based signatures by creating another set of them, BadDNS aims to utilize and support existing repositories of signatures. 

Currently, the ultimate source of many of these signatures is the `https://github.com/EdOverflow/can-i-take-over-xyz` repository. The issues section of this repo has become a centralized discussion place for signatures. Many of these discussions are used to create signatures within Nuclei. Ultimately, these Nuclei signatures are converted and used within BadDNS.

We highly encourage contributions to the signatures on these projects and to the discussions on `can-i-take-over-xyz`, as ultimately these are fed into BadDNS and benefit the entire community.