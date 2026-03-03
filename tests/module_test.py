from baddns.base import BadDNS_base, get_all_modules
from baddns.modules.cname import BadDNS_cname
from baddns.modules.mx import BadDNS_mx
from baddns.modules.ns import BadDNS_ns
from baddns.modules.nsec import BadDNS_nsec
from baddns.modules.references import BadDNS_references
from baddns.modules.txt import BadDNS_txt
from baddns.modules.zonetransfer import BadDNS_zonetransfer


def test_modules_customnameservers():
    modules = get_all_modules()
    for m in modules:
        module_instance = m("bad.dns", custom_nameservers=["1.1.1.1", "8.8.8.8"])
        assert module_instance.target_dnsmanager.dns_client.nameservers == [
            "1.1.1.1",
            "8.8.8.8",
        ], f"setting custom nameservers failed for module: [{m.__name__}]"
    assert modules


def test_base_supported_modes_default():
    assert BadDNS_base.supported_modes == set()


def test_module_supported_modes_values():
    assert BadDNS_cname.supported_modes == {"http", "dns_nxdomain"}
    assert BadDNS_ns.supported_modes == {"dns_nosoa"}
    assert BadDNS_txt.supported_modes == {"http", "dns_nxdomain"}
    assert BadDNS_references.supported_modes == {"http", "dns_nxdomain"}


def test_non_signature_modules_have_empty_supported_modes():
    assert BadDNS_mx.supported_modes == set()
    assert BadDNS_nsec.supported_modes == set()
    assert BadDNS_zonetransfer.supported_modes == set()
