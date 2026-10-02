import yara


class YaraHelper:
    def compile_strings(self, strings, nocase=False):
        yara_strings = []
        for i, s in enumerate(strings):
            s = (
                s.replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
            )
            yara_string = f'$s{i} = "{s}"'
            if nocase:
                yara_string += " nocase"
            yara_strings.append(yara_string)
        yara_strings = "\n        ".join(yara_strings)

        yara_rule = f"""
rule strings_match
{{
    strings:
        {yara_strings}
    condition:
        any of them
}}
"""
        return self.compile(source=yara_rule)

    def compile(self, *args, **kwargs):
        return yara.compile(*args, **kwargs)

    def match(self, compiled_rules, text):
        if isinstance(text, str):
            text = text.encode("utf-8", errors="replace")
        matches = compiled_rules.match(data=text)
        matched_strings = []
        if matches:
            for match in matches:
                for string_match in match.strings:
                    for instance in string_match.instances:
                        matched_strings.append(instance.matched_data.decode("utf-8", errors="replace"))
        return matched_strings
