import logging

from cloudcheck import check as cloudcheck

log = logging.getLogger(__name__)


class BadDNS_base:
    skip_cloud_targets = False

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

    async def dispatch(self):
        if any(label.startswith("_") for label in self.target.split(".")):
            log.debug(f"Skipping SRV-style target [{self.target}], SRV-style subdomains are not supported")
            return False
        if self.skip_cloud_targets and cloudcheck(self.target):
            log.debug(f"Skipping cloud provider target [{self.target}] for module [{self.__class__.__name__}]")
            return False
        return await self._dispatch()

    async def _dispatch(self):
        raise NotImplementedError

    async def cleanup(self):
        pass


def get_all_modules(*args, **kwargs):
    return [m for m in BadDNS_base.__subclasses__()]
