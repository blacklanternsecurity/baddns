from baddns.base import get_all_modules


def test_modules_customnameservers():
    modules = get_all_modules()
    for m in modules:
        module_instance = m("bad.dns", custom_nameservers=["1.1.1.1", "8.8.8.8"])
        assert module_instance.target_dnsmanager.dns_client.nameservers == [
            "1.1.1.1",
            "8.8.8.8",
        ], f"setting custom nameservers failed for module: [{m.__name__}]"
    assert modules
