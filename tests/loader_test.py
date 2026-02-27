import pytest
from baddns.lib.loader import load_signatures
from baddns.lib.errors import BadDNSSignatureException


class TestLoadSignatures:
    def test_nonexistent_directory(self):
        with pytest.raises(BadDNSSignatureException, match="does not exist"):
            load_signatures(signatures_dir="/nonexistent/path")

    def test_no_valid_signatures(self, tmp_path):
        # Create a dir with a non-yml file
        (tmp_path / "notasig.txt").write_text("hello")
        with pytest.raises(BadDNSSignatureException, match="No signatures were successfuly loaded"):
            load_signatures(signatures_dir=str(tmp_path))

    def test_bad_signature_file(self, tmp_path):
        # Create a yml file with invalid signature data (invalid mode)
        (tmp_path / "bad.yml").write_text("service_name: test\nmode: invalid_mode\nsource: self\n")
        with pytest.raises(BadDNSSignatureException, match="No signatures were successfuly loaded"):
            load_signatures(signatures_dir=str(tmp_path))

    def test_default_signatures_load(self):
        sigs = load_signatures()
        assert len(sigs) > 0

    def test_valid_custom_dir(self, tmp_path):
        sig_content = """
service_name: TestSig
mode: dns_nxdomain
source: self
identifiers:
  cnames:
    - type: word
      value: test.example.com
  not_cnames: []
  ips: []
  nameservers: []
"""
        (tmp_path / "test.yml").write_text(sig_content)
        sigs = load_signatures(signatures_dir=str(tmp_path))
        assert len(sigs) == 1
        assert sigs[0].signature["service_name"] == "TestSig"
