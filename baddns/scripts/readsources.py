#!/usr/bin/env python3
"""Convert upstream takeover fingerprints (dnsReaper, nuclei-templates) into baddns signatures.

Run from a directory containing ./dnsReaper and ./nuclei-templates checkouts. Writes:
  signatures_to_test/<shortname>_<name>.yml    converted signatures that passed validation
  signatures_to_test/<shortname>_<name>.notes  (optional) upstream logic that could not be converted
  upstream_manifest.txt                        every upstream template seen, converted or not
  readsources.log                              conversion log
"""

import re
import os
import ast
import sys
import ipaddress
import yaml
import logging

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from lib.signature import BadDNSSignature  # noqa: E402
from lib.errors import BadDNSSignatureException  # noqa: E402

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

OUTPUT_DIRECTORY = "signatures_to_test"
MANIFEST_FILE = "upstream_manifest.txt"

# Takeover-tagged nuclei templates that are generic detectors, not service fingerprints
NUCLEI_SKIP = {
    "detect-dangling-cname",
    "servfail-refused-hosts",
    "gcloud-dns-dangling-records",
    "microsoft-azure-error",
    "aws-redirect",
    "godaddy-parked-domain",  # parked-domain detection is tracked separately (#391)
}

DSL_NOOP = {"Host != ip"}
DSL_CNAME_CONTAINS = re.compile(r"""^contains\(\s*cname\s*,\s*["']([^"']+)["']\s*\)$""")


def is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def empty_identifiers():
    return {"cnames": [], "not_cnames": [], "ips": [], "nameservers": []}


def write_signature(shortname, signature_name, signature_data, notes):
    """Validate, then write the signature (and any conversion notes). Returns True if written."""
    output_path = os.path.join(OUTPUT_DIRECTORY, f"{shortname}_{signature_name}.yml")
    candidate = BadDNSSignature()
    try:
        candidate.initialize(**signature_data)
    except BadDNSSignatureException as e:
        logger.info(f"Skipping [{output_path}]: failed validation: [{e}]")
        return False

    output = candidate.output()
    if not output.get("negative_signature"):
        output.pop("negative_signature", None)
    with open(output_path, "w") as f:
        yaml.dump(output, f)
    logger.info(f"Wrote [{output_path}]:\n{yaml.dump(output)}")

    notes_path = os.path.join(OUTPUT_DIRECTORY, f"{shortname}_{signature_name}.notes")
    if notes:
        with open(notes_path, "w") as f:
            f.write("\n".join(f"- {n}" for n in notes) + "\n")
    return True


class NucleiTemplatesTransformer:
    shortname = "nucleitemplates"

    def __init__(self, template):
        self.template = template
        self.notes = []
        self.identifiers = empty_identifiers()

    def _add_cname(self, value):
        value = value.lstrip(".")
        if value and {"type": "word", "value": value} not in self.identifiers["cnames"]:
            self.identifiers["cnames"].append({"type": "word", "value": value})

    def _dsl(self, matcher):
        negative = matcher.get("negative", False)
        for expr in matcher.get("dsl", []):
            expr = expr.strip()
            if expr in DSL_NOOP:
                continue
            m = DSL_CNAME_CONTAINS.match(expr)
            if m and not negative:
                self._add_cname(m.group(1))
                continue
            # Host exclusions refer to the scanned host, which baddns handles differently;
            # they must never be inverted into required or excluded CNAMEs.
            self.notes.append(f"dropped {'negative ' if negative else ''}DSL: `{expr}`")

    def _http_matchers(self, http):
        converted = []
        for matcher in http.get("matchers", []):
            mtype = matcher.get("type")
            part = matcher.get("part", "body")
            negative = matcher.get("negative", False)

            if mtype == "dsl":
                self._dsl(matcher)
                continue
            if matcher.get("case-insensitive"):
                self.notes.append(f"`case-insensitive` ignored on {mtype} matcher (baddns matches case-sensitively)")

            if mtype == "word":
                words = list(matcher.get("words", []))
                if part in ("host", "cname"):
                    if negative:
                        self.notes.append(f"dropped negative {part} words: {words}")
                    else:
                        for w in words:
                            self._add_cname(w)
                    continue
                if part == "content_type":
                    words = [f"content-type: {w}" for w in words]
                    part = "header"
                entry = {"type": "word", "part": part, "words": words, "condition": matcher.get("condition", "or")}
                if negative:
                    entry["negative"] = True
                converted.append(entry)
            elif mtype == "regex":
                if part in ("host", "cname"):
                    self.notes.append(f"dropped regex on part {part}: {matcher.get('regex')}")
                    continue
                entry = {
                    "type": "regex",
                    "part": "header" if part == "content_type" else part,
                    "regex": list(matcher.get("regex", [])),
                    "condition": matcher.get("condition", "or"),
                }
                if negative:
                    entry["negative"] = True
                converted.append(entry)
            elif mtype == "status":
                statuses = matcher.get("status", [])
                statuses = statuses if isinstance(statuses, list) else [statuses]
                if not statuses:
                    continue
                if len(statuses) > 1:
                    self.notes.append(f"only first status kept from {statuses}")
                entry = {"type": "status", "status": statuses[0]}
                if negative:
                    entry["negative"] = True
                converted.append(entry)
            else:
                self.notes.append(f"dropped unsupported matcher type `{mtype}`")
        return converted

    def _dns_identifiers(self, dns):
        for matcher in dns.get("matchers", []):
            mtype = matcher.get("type")
            if mtype == "dsl":
                self._dsl(matcher)
            elif mtype == "word":
                for word in matcher.get("words", []):
                    if word == "NXDOMAIN":
                        continue
                    if is_ip_address(word):
                        self.identifiers["ips"].append({"type": "word", "value": word})
                    else:
                        self._add_cname(word)
            elif mtype == "regex":
                self.notes.append(f"dropped regex CNAME identifiers (not supported yet, #934): {matcher.get('regex')}")

    def map_values(self):
        values = {
            "service_name": self.template["info"]["name"],
            "source": self.shortname,
            "identifiers": self.identifiers,
            "mode": None,
            "matcher_rule": None,
        }
        if "http" in self.template:
            values["mode"] = "http"
            requests = self.template["http"]
            http = requests[0]
            if len(requests) > 1:
                self.notes.append(f"only the first of {len(requests)} http requests was converted")
            if len(http.get("path", [])) > 1:
                self.notes.append("only the base path is requested by baddns; extra paths ignored")
            matchers = self._http_matchers(http)
            values["matcher_rule"] = {
                "matchers-condition": http.get("matchers-condition", "or"),
                "matchers": matchers,
            }
        elif "dns" in self.template:
            values["mode"] = "dns_nxdomain"
            self._dns_identifiers(self.template["dns"][0])
        return values


class DnsReaperSignatureTransformer:
    shortname = "dnsreaper"
    use_case_to_mode_mapping = {
        "cname_found_but_string_in_body": "http",
        "cname_found_but_status_code": "http",
        "cname_or_ip_found_but_string_in_body": "http",
        "ip_found_but_string_in_body": "http",
        "cname_found_but_NX_DOMAIN": "dns_nxdomain",
        "ns_found_but_no_SOA": "dns_nosoa",
    }

    def __init__(self, source):
        self.notes = []
        self.data = {}
        self.variables = {}
        self._visit(ast.parse(source))

    @staticmethod
    def _const(node):
        return node.value if isinstance(node, ast.Constant) else None

    @staticmethod
    def _clean_cname(value):
        value = value.lstrip(".")
        return value[len("cname.") :] if value.startswith("cname.") else value

    def map_values(self):
        values = {}
        identifiers = empty_identifiers()
        matchers = []
        for key, value in self.data.items():
            if key == "http_strings":
                for http_string in value:
                    matchers.append({"type": "word", "words": [http_string], "condition": "or", "part": "body"})
            elif key == "status_code" and value is not None:
                if value == 0:
                    # dnsReaper's code=0 means "TLS/connection failed", which baddns can't match on yet
                    self.notes.append("dropped `code=0` (TLS/connection-failure check, not supported yet)")
                else:
                    matchers.append({"type": "status", "status": int(value)})
            elif key in identifiers:
                identifiers[key] = value
            elif key == "use_case":
                values["mode"] = self.use_case_to_mode_mapping.get(value, value)
            elif key in ("service_name",):
                values[key] = value
        values["source"] = self.shortname
        values["identifiers"] = identifiers
        if matchers:
            values["matcher_rule"] = {"matchers-condition": "and", "matchers": matchers}
        return values

    def _visit(self, node):
        visitor = getattr(self, "_visit_" + node.__class__.__name__, None)
        if visitor:
            visitor(node)
        for child in ast.iter_child_nodes(node):
            self._visit(child)

    def _visit_Assign(self, node):
        if node.targets and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if isinstance(node.value, ast.List) and all(isinstance(e, ast.Constant) for e in node.value.elts):
                self.variables[name] = [e.value for e in node.value.elts]
            elif isinstance(node.value, ast.Constant):
                self.variables[name] = [node.value.value]

    def _visit_List(self, node):
        ips = [e.value for e in node.elts if isinstance(e, ast.Constant) and is_ip_address(str(e.value))]
        if ips:
            self.data.setdefault("ips", [])
            self.data["ips"] += [ip for ip in ips if ip not in self.data["ips"]]

    def _resolve_list(self, node):
        if isinstance(node, ast.Constant):
            return [node.value]
        if isinstance(node, ast.List):
            return [e.value for e in node.elts if isinstance(e, ast.Constant)]
        if isinstance(node, ast.Name):
            return list(self.variables.get(node.id, []))
        return []

    def _visit_Call(self, call):
        func = call.func
        use_case = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else None)
        if use_case not in self.use_case_to_mode_mapping:
            return
        self.data["use_case"] = use_case
        kwargs = {kw.arg: kw.value for kw in call.keywords}
        if "service" in kwargs:
            self.data["service_name"] = self._const(kwargs["service"])
        if "domain_not_configured_message" in kwargs:
            message = self._const(kwargs["domain_not_configured_message"])
            self.data["http_strings"] = [message] if message else []
        if "code" in kwargs:
            self.data["status_code"] = self._const(kwargs["code"])
        if "cname" in kwargs:
            self.data["cnames"] = [
                {"type": "word", "value": self._clean_cname(v)} for v in self._resolve_list(kwargs["cname"]) if v
            ]
        if "ns" in kwargs:
            self.data["nameservers"] = self._resolve_list(kwargs["ns"])
        # positional list arguments are nameserver lists; IPs are collected by _visit_List
        for arg in call.args:
            if isinstance(arg, (ast.List, ast.Name)):
                self.data["nameservers"] = self._resolve_list(arg)


def nuclei_template_files(root):
    for base in ("http/takeovers", "dns"):
        for dirpath, _, filenames in os.walk(os.path.join(root, base)):
            for filename in sorted(filenames):
                if filename.endswith(".yaml"):
                    yield os.path.join(dirpath, filename)


def is_takeover_template(template, filepath):
    tags = template.get("info", {}).get("tags", "")
    tags = tags if isinstance(tags, list) else [t.strip() for t in str(tags).split(",")]
    return "takeover" in tags or "-takeover" in os.path.basename(filepath)


def main():
    handler = logging.FileHandler("readsources.log")
    handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)
    os.makedirs(OUTPUT_DIRECTORY, exist_ok=True)
    manifest = []
    logger.info("readsources init")

    dnsreaper_dir = "./dnsReaper/signatures"
    logger.info(f"Starting dnsReaper ingest from [{os.path.abspath(dnsreaper_dir)}]")
    for filename in sorted(os.listdir(dnsreaper_dir)):
        if filename.startswith("_") or not filename.endswith(".py"):
            continue
        name = filename[: -len(".py")]
        manifest.append(f"dnsreaper_{name}.yml")
        with open(os.path.join(dnsreaper_dir, filename)) as f:
            transformer = DnsReaperSignatureTransformer(f.read())
        write_signature("dnsreaper", name, transformer.map_values(), transformer.notes)

    nuclei_dir = "./nuclei-templates"
    logger.info(f"Starting nuclei-templates ingest from [{os.path.abspath(nuclei_dir)}]")
    for filepath in nuclei_template_files(nuclei_dir):
        name = os.path.basename(filepath)[: -len(".yaml")]
        if name in NUCLEI_SKIP:
            continue
        with open(filepath) as f:
            template = yaml.safe_load(f)
        if not isinstance(template, dict) or not is_takeover_template(template, filepath):
            continue
        manifest.append(f"nucleitemplates_{name}.yml")
        logger.info(f"loading nuclei-template [{filepath}]")
        transformer = NucleiTemplatesTransformer(template)
        write_signature("nucleitemplates", name, transformer.map_values(), transformer.notes)

    with open(MANIFEST_FILE, "w") as f:
        f.write("\n".join(sorted(manifest)) + "\n")
    logger.info("readsources complete")


if __name__ == "__main__":
    main()
