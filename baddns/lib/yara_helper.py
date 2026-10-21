import yara


class YaraHelper:
    def compile(self, *args, **kwargs):
        return yara.compile(*args, **kwargs)
