import logging

from cloudcheck import CloudCheck

log = logging.getLogger(__name__)


class BadDNS_base:
    skip_cloud_targets = False

    def __init__(
        self,
        target,
        http_client=None,
        dns_client=None,
        signatures=None,
        custom_nameservers=None,
        cli=False,
        **kwargs,
    ):
        self.target = self.set_target(target)
        self.http_client = http_client
        self.dns_client = dns_client
        self.signatures = signatures
        self.custom_nameservers = custom_nameservers
        self.parent_class = kwargs.get("parent_class", "self")
        self.cli = cli
        self.disable_negative_signatures = kwargs.get("disable_negative_signatures", False)
        # Set only by the DELEGATION module for the labels it builds itself; never for incoming targets
        self.allow_delegation_labels = kwargs.get("allow_delegation_labels", False)

    # hook to allow external manipulation of target assignment
    def set_target(self, target):
        return target

    def infomsg(self, msg):
        if self.cli:
            log.info(msg)
        else:
            log.debug(msg)

    @staticmethod
    def is_delegation_label(target):
        """True for _acme-challenge.<domain>, _dmarc.<domain> and <selector>._domainkey.<domain>, with no other underscore labels."""
        labels = target.split(".")
        underscored = [i for i, label in enumerate(labels) if label.startswith("_")]
        if underscored == [0] and labels[0] in ("_acme-challenge", "_dmarc"):
            return True
        return underscored == [1] and labels[1] == "_domainkey" and not labels[0].startswith("_")

    async def dispatch(self):
        delegation_ok = self.allow_delegation_labels and self.is_delegation_label(self.target)
        if not delegation_ok and any(label.startswith("_") for label in self.target.split(".")):
            log.debug(f"Skipping SRV-style target [{self.target}], SRV-style subdomains are not supported")
            return False
        if self.skip_cloud_targets and await CloudCheck().lookup(self.target):
            log.debug(f"Skipping cloud provider target [{self.target}] for module [{self.__class__.__name__}]")
            return False
        return await self._dispatch()

    async def _dispatch(self):
        raise NotImplementedError

    async def cleanup(self):
        pass


def get_all_modules(*args, **kwargs):
    seen = []

    def _walk(cls):
        for sub in cls.__subclasses__():
            # Only concrete modules have a `name` class attribute; intermediate
            # bases like BadDNS_email_base do not.
            if getattr(sub, "name", None) and sub not in seen:
                seen.append(sub)
            _walk(sub)

    _walk(BadDNS_base)
    return seen
