import logging

log = logging.getLogger(__name__)


class BadDNS_base:
    def __init__(
        self,
        target,
        http_client_class=None,
        dns_client=None,
        signatures=None,
        custom_nameservers=None,
        cli=False,
        **kwargs,
    ):
        self.target = self.set_target(target)
        self.http_client_class = http_client_class
        self.dns_client = dns_client
        self.signatures = signatures
        self.custom_nameservers = custom_nameservers
        self.parent_class = kwargs.get("parent_class", "self")
        self.cli = cli

    # hook to allow external manipulation of target assignment
    def set_target(self, target):
        return target

    def infomsg(self, msg):
        if self.cli:
            log.info(msg)
        else:
            log.debug(msg)


def get_all_modules(*args, **kwargs):
    return [m for m in BadDNS_base.__subclasses__()]
