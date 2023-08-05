#!/usr/bin/env python3
import re
import os
import ast
import sys
import ipaddress
import yaml
import logging
from abc import ABC, abstractmethod

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from lib.signature import BadDNSSignature
from lib.errors import BadDNSSignatureException

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.FileHandler("readsources.log")
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


class Transformer(ABC):
    @abstractmethod
    def transform(self, input_data):
        pass

    def writeSignature(self, shortname, signatureName):
        output_directory = "signatures_to_test"
        os.makedirs(output_directory, exist_ok=True)  # Creates the directory if it does not exist
        output_file_path = os.path.join(output_directory, f"{shortname}_{signatureName}.yml")
        with open(output_file_path, "w") as f:
            signature_candidate = BadDNSSignature()
            signature_data = self.map_values()
            logger.info(f"Got signature data: [{signature_data}]")
            try:
                signature_candidate.initialize(**signature_data)
            except BadDNSSignatureException as e:
                logger.info(f"Error encountered validating signature data: [{e}]")

            logger.info(
                f"Signature data validated. Final signature: \n****************************{yaml.dump(signature_candidate.output())}\n****************************"
            )
            logger.info(f"writing to: [{output_file_path}]")
            yaml.dump(signature_candidate.output(), f)

    def _is_ip_address(self, value):
        try:
            ipaddress.IPv4Address(value)
            return True
        except ipaddress.AddressValueError:
            pass

        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            pass

        return False


class NucleiTemplatesTransformer(Transformer):
    def transform(self, signature_data):
        self.shortname = "nucleitemplates"
        self.data = {"source": self.shortname}
        self.nucleiconvert()

    def parse_dsl(self, dsl_rule):
        # contains host regex
        host_regex = re.compile(r'\!contains\(host,"(?P<domain>.+?)\"\)')
        host_regex_match = host_regex.match(dsl_rule)
        if host_regex_match:
            return host_regex_match.group("domain"), "to_cname"
        return None, None

    def map_values(self):
        values = {
            "service_name": data["info"]["name"],
            "source": "nucleitemplates",
            "identifiers": {"cnames": [], "not_cnames": [], "ips": [], "nameservers": []},
            "mode": None,
            "matcher_rule": None,
        }

        if "http" in data.keys():
            values["mode"] = "http"

            http_data = data["http"][0]
            if "matchers" in http_data.keys():
                matcher_rule = {
                    "matchers-condition": http_data.get("matchers-condition", "and"),
                    "matchers": [],
                }
                for matcher in http_data["matchers"]:
                    # Ignore unknown types
                    if matcher["type"] not in ["status", "word", "regex", "dsl"]:
                        continue

                    if matcher["type"] == "word":
                        matcher["part"] = matcher.get("part", "body")

                        if matcher["part"] == "host":
                            negative = matcher.get("negative", False)

                            for w in matcher["words"]:
                                if negative:
                                    values["identifiers"]["not_cnames"].append({"type": "word", "value": w})
                                else:
                                    values["identifiers"]["cnames"].append({"type": "word", "value": w})
                            continue

                        matcher["condition"] = matcher.get("condition", "and")
                    if matcher["type"] == "dsl":
                        for dsl_rule in matcher["dsl"]:
                            parsed_dsl, dsl_type = self.parse_dsl(dsl_rule)

                            if dsl_type == "to_cname":
                                values["identifiers"]["cnames"].append({"type": "word", "value": parsed_dsl})

                    if matcher["type"] == "status":
                        matcher["status"] = matcher["status"][0]

                    matcher_rule["matchers"].append(matcher)
                values["matcher_rule"] = matcher_rule
        elif "dns" in data.keys():
            values["mode"] = "dns_nxdomain"
            dns_data = data["dns"][0]
            if "matchers" in dns_data.keys():
                for matcher in dns_data["matchers"]:
                    if matcher["type"] == "word":
                        for word in matcher.get("words", []):
                            if word != "NXDOMAIN":
                                if self._is_ip_address(word):
                                    values["identifiers"]["ips"].append({"type": "word", "value": word})
                                else:
                                    values["identifiers"]["cnames"].append({"type": "word", "value": word})
                    elif matcher["type"] == "regex":
                        for regex_str in matcher.get("regex", []):
                            values["identifiers"]["cnames"].append(
                                {"type": "regex", "value": regex_str.replace("CNAME\t", "")}
                            )
        return values


class DnsReaperSignatureTransformer(Transformer):
    use_case_to_mode_mapping = {
        "cname_found_but_string_in_body": "http",
        "cname_found_but_status_code": "http",
        "cname_or_ip_found_but_string_in_body": "http",
        "ip_found_but_string_in_body": "http",
        "cname_found_but_NX_DOMAIN": "dns_nxdomain",
        "ns_found_but_no_SOA": "dns_nosoa",
    }

    def transform(self, signature_data):
        self.shortname = "dnsreaper"
        self.data = {"source": self.shortname}
        self.variables = {}
        self._visit(ast.parse(signature_data))

    def map_values(self):
        values = {}
        identifiers = {"cnames": [], "not_cnames": [], "ips": [], "nameservers": []}

        for key, value in self.data.items():
            if key == "http_strings" and value:
                if isinstance(value, list):
                    for http_string in value:
                        values.setdefault("matcher_rule", {"matchers-condition": "and", "matchers": []})[
                            "matchers"
                        ].append({"type": "word", "words": [http_string], "condition": "or", "part": "body"})
                else:
                    values.setdefault("matcher_rule", {"matchers-condition": "and", "matchers": []})[
                        "matchers"
                    ].append({"type": "word", "words": [value], "condition": "or", "part": "body"})
            elif key == "status_code" and value is not None:
                values.setdefault("matcher_rule", {"matchers-condition": "and", "matchers": []})["matchers"].append(
                    {"type": "status", "status": int(value)}
                )

            elif key in ["ips", "nameservers", "cnames", "not_cnames"]:
                identifiers[key] = value

            elif key == "use_case":
                values["mode"] = self.use_case_to_mode_mapping.get(value, value)
            else:
                values[key] = value

        values["identifiers"] = identifiers
        return values

    def _visit(self, node):
        method = "_visit_" + node.__class__.__name__
        visitor = getattr(self, method, self._visit_generic)
        visitor(node)

        for child in ast.iter_child_nodes(node):
            self._visit(child)

    def _visit_generic(self, node):
        pass

    def _visit_Assign(self, node):
        if len(node.targets) > 0 and isinstance(node.targets[0], ast.Name):
            target_var_name = node.targets[0].id
            if isinstance(node.value, ast.List) and all(isinstance(elt, ast.Constant) for elt in node.value.elts):
                self.variables[target_var_name] = [elt.value for elt in node.value.elts]
            elif isinstance(node.value, ast.Constant):
                self.variables[target_var_name] = [node.value.value]

    def _visit_List(self, node):
        ips = [elt.s for elt in node.elts if isinstance(elt, ast.Str) and self._is_ip_address(elt.s)]
        if ips:
            if "ips" in self.data.keys():
                self.data["ips"] += ips
            else:
                self.data["ips"] = ips

    def _visit_Call(self, node):
        call = node
        self.data["use_case"] = (
            call.func.id
            if isinstance(call.func, ast.Name)
            else (call.func.attr if isinstance(call.func, ast.Attribute) else None)
        )
        self.data["service_name"] = next(
            (kw.value.s for kw in call.keywords if kw.arg == "service" and isinstance(kw.value, ast.Str)), None
        )
        self.data["http_strings"] = [
            kw.value.s
            for kw in call.keywords
            if kw.arg == "domain_not_configured_message" and isinstance(kw.value, ast.Str)
        ]
        self.data["https"] = next(
            (kw.value.id for kw in call.keywords if kw.arg == "https" and isinstance(kw.value, ast.Name)), None
        )

        for kw in call.keywords:
            if kw.arg == "cname":
                if isinstance(kw.value, ast.Str):
                    self.data["cnames"] = [{"type": "word", "value": kw.value.s.replace("cname.", "").lstrip(".")}]

                elif isinstance(kw.value, ast.List):
                    self.data["cnames"] = [
                        {"type": "word", "value": elt.s.replace("cname.", "").lstrip(".")} for elt in kw.value.elts
                    ]

                elif isinstance(kw.value, ast.Name):
                    self.data["cnames"] = [
                        {"type": "word", "value": val.replace("cname.", "").lstrip(".")}
                        for val in self.variables.get(kw.value.id, [])
                    ]

        if call.args:  # Check for positional arguments
            for arg in call.args:
                if isinstance(arg, ast.List):
                    self.data["nameservers"] = [elt.s for elt in arg.elts]

        ns_val = next((kw.value for kw in call.keywords if kw.arg == "ns"), None)
        if ns_val:
            if isinstance(ns_val, ast.Str):
                self.data["nameservers"] = [ns_val.s]
            elif isinstance(ns_val, ast.List):
                self.data["nameservers"] = [elt.s for elt in ns_val.elts]
        self.data["sample_nameserver"] = next(
            (kw.value.s for kw in call.keywords if kw.arg == "sample_ns" and isinstance(kw.value, ast.Str)), None
        )
        self.data["status_code"] = next(
            (kw.value.n for kw in call.keywords if kw.arg == "code" and isinstance(kw.value, ast.Num)), None
        )

        for arg in call.args:
            if isinstance(arg, ast.List):
                self._visit_List(arg)


directory = "./dnsReaper/signatures"
logger.info("readsources init")
logger.info(f"Starting dnsReaper ingest, reading from: {os.path.join(os.getcwd(), directory)}")

files = os.listdir(directory)

for filename in files:
    logger.info(f"loading dnsReaper signature [{filename}]")
    if not filename.startswith("_") and filename.endswith(".py"):
        dnsReaper_transformer = DnsReaperSignatureTransformer()
        with open(f"{directory}/{filename}") as f:
            dnsReaper_transformer.transform(f.read())
            dnsReaper_transformer.writeSignature("dnsreaper", filename.split(".")[0])


directory_http = "./nuclei-templates/http/takeovers"
directory_dns = "./nuclei-templates/dns"

logger.info(
    f"Starting nuclei-templates ingest, reading from: [{os.path.join(os.getcwd(), directory_http)}] and [{os.path.join(os.getcwd(), directory_dns)}]"
)

files_http = os.listdir(os.path.expanduser(directory_http))
files_dns = os.listdir(os.path.expanduser(directory_dns))

files = []
for filename in files_http:
    files.append(os.path.join(directory_http, filename))
for filename in files_dns:
    files.append(os.path.join(directory_dns, filename))

for filepath in files:
    if "-takeover" in filepath and filepath.endswith(".yaml"):
        logger.info(f"loading nuclei-template [{filename}]")
        with open(filepath, "r") as file:
            data = yaml.safe_load(file)
        nucleitemplates_transformer = NucleiTemplatesTransformer()
        nucleitemplates_transformer.writeSignature("nucleitemplates", filepath.split("/")[-1].split(".")[0])

logger.info("readsources complete")
