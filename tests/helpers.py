import os
import dns
import pkg_resources


def mock_process_answer(self, answer, rdatatype):
    return answer


class MockDNSWalk:
    def __init__(self, mock_dnswalk_data=[]):
        print("??????????????")
        print(mock_dnswalk_data)
        self.mock_dnswalk_data = mock_dnswalk_data

    async def ns_trace(self, target):
        print(target)
        self.mock_dnswalk_data


class MockResolver:
    def __init__(self, mock_data=None):
        self.mock_data = mock_data if mock_data else {}
        self.nameservers = ["127.0.0.2"]

    async def resolve(self, query_name, rdtype_obj=None):
        query_name_str = str(query_name)

        # Check for _NXDOMAIN
        if "_NXDOMAIN" in self.mock_data and query_name_str in self.mock_data["_NXDOMAIN"]:
            # Simulate the NXDOMAIN exception
            raise dns.resolver.NXDOMAIN

        if rdtype_obj is None:
            rdtype = "A"
        elif isinstance(rdtype_obj, str):
            rdtype = rdtype_obj.upper()
        else:
            rdtype = str(rdtype_obj.name).upper()

        # Fetch the relevant mock data based on query_name and rdtype
        results = self.mock_data.get(query_name_str, {}).get(rdtype, [])

        # Strip trailing dots from the results for domains
        return [result.rstrip(".") for result in results]


def mock_signature_load(fs, signature_filename):
    fake_dir = "/tmp/signatures"
    fs.create_dir(fake_dir)
    signatures_dir = pkg_resources.resource_filename("baddns", "signatures")
    signature_file = os.path.join(signatures_dir, signature_filename)
    fs.add_real_file(signature_file)
    os.symlink(signature_file, os.path.join(fake_dir, signature_filename))


class MockWhois:
    pass
