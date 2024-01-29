# BadDNS
Check subdomains for for subdomain takeovers and other DNS tomfoolery

[![Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
![License](https://img.shields.io/badge/license-GPLv3-f126ea.svg)
[![tests](https://github.com/blacklanternsecurity/baddns/actions/workflows/tests.yaml/badge.svg)](https://github.com/blacklanternsecurity/baddns/actions/workflows/tests.yaml)

<p align="left"><img width="300" height="300" src="https://github.com/blacklanternsecurity/baddns/assets/24899338/2ca1fe25-e834-4df8-8b02-8bf8f60f6e31"></p>

BadDNS is a standalone tool and [BBOT](https://github.com/blacklanternsecurity/bbot) module for detecting domain/subdomain takeovers of all kinds, including other DNS issues like NSEC walks and Subdomain Takeovers. 

## usage 

```
baddns [-h] [-n CUSTOM_NAMESERVERS] [-c CUSTOM_SIGNATURES] [-l] [-m MODULES] [-d] [target]

positional arguments:
  target                subdomain to analyze

options:
  -h, --help            show this help message and exit
  -n CUSTOM_NAMESERVERS, --custom-nameservers CUSTOM_NAMESERVERS
                        Provide a list of custom nameservers separated by comma.
  -c CUSTOM_SIGNATURES, --custom-signatures CUSTOM_SIGNATURES
                        Use an alternate directory for loading signatures
  -l, --list-modules    List available modules and their descriptions.
  -m MODULES, --modules MODULES
                        Comma separated list of module names to use. Ex: module1,module2,module3
  -d, --debug           Enable debug logging

```

Please visit our [documentation](https://www.blacklanternsecurity.com/baddns) for many more details.
