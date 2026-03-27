from baddns.base import get_all_modules


def test_modules_customnameservers():
    modules = get_all_modules()
    for m in modules:
        module_instance = m("bad.dns", custom_nameservers=["1.1.1.1", "8.8.8.8"])
        # blastdns Client appends port to resolvers, so check they contain the IPs
        resolvers = module_instance.target_dnsmanager.dns_client.resolvers
        assert any("1.1.1.1" in r for r in resolvers), f"setting custom nameservers failed for module: [{m.__name__}]"
        assert any("8.8.8.8" in r for r in resolvers), f"setting custom nameservers failed for module: [{m.__name__}]"
    assert modules
