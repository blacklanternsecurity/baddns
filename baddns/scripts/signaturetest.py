import os
import sys
import yaml
import json
import string
import random
import httpx
import dns.resolver

rand_pool = string.ascii_lowercase

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from lib.signature import BadDNSSignature
from lib.matcher import Matcher
from lib.errors import BadDNSSignatureException


def dns_request(domain):
    try:
        answers = dns.resolver.resolve(domain, "A")
        return [answer.to_text() for answer in answers]

    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"

    except dns.resolver.Timeout:
        return "Timeout"

    except dns.resolver.NoAnswer:
        return "NoAnswer"

    except dns.resolver.NoNameservers:
        return "NoNameservers"

    except Exception as e:
        return str(e)


testsig = """
identifiers:
  cnames:
  - helpscoutdocs.com
  ips: []
  nameservers: []
matcher_rule:
  matchers:
  - condition: or
    part: body
    type: word
    words:
    - Not Found
  matchers-condition: and
mode: http
service_name: helpscoutdocs.com
source: dnsreaper
"""


def rand_string(length=12):
    return "".join([random.choice(rand_pool) for _ in range(int(length))])


yaml_data = yaml.safe_load(testsig)
match_table = {}


headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Pragma": "no-cache",
    "Upgrade-Insecure-Requests": "1",
}


def process_file(file_path):
    error = None
    signature_pass = False

    with open(file_path, "r") as file:
        sig_to_test = file.read()

    sig = BadDNSSignature()
    sig_yaml = yaml.safe_load(sig_to_test)
    try:
        sig.initialize(**sig_yaml)
    except BadDNSSignatureException as e:
        return False, {}, f"Failed Signature Validation: [{e}]"

    if sig.signature["mode"] == "http":
        matcher_rule = sig.signature["matcher_rule"]
        matcher = Matcher(matcher_rule)
        if len(sig.signature["identifiers"]["cnames"]) > 0:
            for cname_dict in sig.signature["identifiers"]["cnames"]:
                if cname_dict["type"] == "word":
                    cname = cname_dict["value"]
                    match_found = False
                    for scheme in ("http", "https"):
                        for follow_redirects in [True, False]:
                            try:
                                url = f"{scheme}://{rand_string()}.{cname}"
                                r = httpx.get(url, headers=headers, follow_redirects=follow_redirects, timeout=5)
                                if matcher.is_match(r):
                                    match_found = True
                            except (httpx.ConnectError, httpx.ReadTimeout):
                                pass
                    if match_found:
                        signature_pass = True
                        match_table[cname] = True
                    else:
                        match_table[cname] = False
                else:
                    pass
                    # TODO: Support other types
        else:
            signature_pass = True
        if signature_pass == False:
            error = "No CNAMES passed random subdomain matcher validation"

    elif sig.signature["mode"] == "dns_nxdomain":
        for cname_dict in sig.signature["identifiers"]["cnames"]:
            if cname_dict["type"] == "word":
                cname = cname_dict["value"]
                test_domain = f"{rand_string()}.{cname}"
                r = dns_request(test_domain)
                if r == "NXDOMAIN":
                    signature_pass = True
                    match_table[cname] = True
                else:
                    match_table[cname] = False
        if signature_pass == False:
            error = "No CNAMES gave expected NXDOMAIN response"

    elif sig.signature["mode"] == "dns_nosoa":
        signature_pass = True

    return signature_pass, match_table, error


def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <input_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    signature_pass, match_table, error = process_file(file_path)

    # Convert results to JSON and print
    result = {
        "signature_pass": signature_pass,
        "match_table": match_table,
        "error": error,
    }
    print(json.dumps(result))


if __name__ == "__main__":
    main()
