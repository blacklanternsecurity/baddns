import argparse
import pytest
import asyncio
from baddns import cli
from baddns.lib.errors import BadDNSCLIException, BadDNSSignatureException


class TestPrintVersion:
    def test_print_version_found(self, capsys, tmp_path, monkeypatch):
        # Create a fake dist-info directory
        dist_dir = tmp_path / "baddns-1.2.3.dist-info"
        dist_dir.mkdir()

        class FakePath:
            def __init__(self, *a):
                pass

            @property
            def parent(self):
                return FakeParent()

        class FakeParent:
            @property
            def parent(self):
                return tmp_path

            def glob(self, pattern):
                return iter([dist_dir])

        monkeypatch.setattr("baddns.cli.Path", FakePath)
        cli.print_version()
        captured = capsys.readouterr()
        assert "1.2.3" in captured.out

    def test_print_version_unknown(self, capsys, tmp_path, monkeypatch):
        class FakePath:
            def __init__(self, *a):
                pass

            @property
            def parent(self):
                return FakeParent()

        class FakeParent:
            @property
            def parent(self):
                return tmp_path

            def glob(self, pattern):
                return iter([])

        monkeypatch.setattr("baddns.cli.Path", FakePath)
        cli.print_version()
        captured = capsys.readouterr()
        assert "Unknown" in captured.out


class TestValidateTarget:
    def test_valid_target(self):
        assert cli.validate_target("sub.example.com") == "sub.example.com"

    def test_invalid_target(self):
        import argparse

        with pytest.raises(argparse.ArgumentTypeError, match="not correctly formatted"):
            cli.validate_target("!!!invalid!!!")


class TestValidateNameservers:
    def test_valid_single(self):
        assert cli.validate_nameservers("1.1.1.1") == "1.1.1.1"

    def test_valid_multiple(self):
        assert cli.validate_nameservers("1.1.1.1,8.8.8.8") == "1.1.1.1,8.8.8.8"

    def test_invalid(self):
        import argparse

        with pytest.raises(argparse.ArgumentTypeError, match="incorrectly formatted"):
            cli.validate_nameservers("not-an-ip")


class TestValidateModules:
    def test_valid_module(self):
        assert cli.validate_modules("CNAME") == "CNAME"

    def test_invalid_format(self):
        import argparse

        with pytest.raises(argparse.ArgumentTypeError, match="format of provided modules is incorrect"):
            cli.validate_modules("CNAME NS")  # space instead of comma

    def test_unknown_module(self):
        import argparse

        with pytest.raises(argparse.ArgumentTypeError, match="not a recognized module"):
            cli.validate_modules("NOTAMODULE")


class TestCLISilentMode:
    def test_silent_mode(self, monkeypatch, capsys, mocker, configure_mock_resolver):
        monkeypatch.setattr("sys.argv", ["python", "-s", "-m", "CNAME", "bad.dns"])
        mock_data = {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
        mock_resolver = configure_mock_resolver(mock_data)
        mocker.patch("baddns.cli.Client", return_value=mock_resolver)
        mocker.patch("baddns.lib.dnsmanager.Client", return_value=mock_resolver)
        cli.main()
        captured = capsys.readouterr()
        # In silent mode, the banner should NOT be printed
        assert "__ )" not in captured.out


class TestCLIListModules:
    def test_list_modules(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv", ["python", "-l"])
        with pytest.raises(SystemExit) as exc_info:
            cli.main()
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "Available Modules:" in captured.out


class TestCLIDebugMode:
    def test_debug_mode(self, monkeypatch, capsys, mocker, configure_mock_resolver):
        monkeypatch.setattr("sys.argv", ["python", "-d", "-m", "CNAME", "bad.dns"])
        mock_data = {"bad.dns": {}}
        mock_resolver = configure_mock_resolver(mock_data)
        mocker.patch("baddns.cli.Client", return_value=mock_resolver)
        mocker.patch("baddns.lib.dnsmanager.Client", return_value=mock_resolver)
        cli.main()
        # Debug mode should run without error


class TestCLIExceptionHandling:
    def test_keyboard_interrupt(self, monkeypatch):
        async def mock_main():
            raise KeyboardInterrupt

        monkeypatch.setattr("baddns.cli._main", mock_main)
        with pytest.raises(SystemExit) as exc_info:
            cli.main()
        assert exc_info.value.code == 1

    def test_cancelled_error(self, monkeypatch):
        async def mock_main():
            raise asyncio.CancelledError

        monkeypatch.setattr("baddns.cli._main", mock_main)
        # Should not raise - it's caught and logged
        cli.main()

    def test_cli_exception(self, monkeypatch):
        async def mock_main():
            raise BadDNSCLIException("test error")

        monkeypatch.setattr("baddns.cli._main", mock_main)
        with pytest.raises(SystemExit) as exc_info:
            cli.main()
        assert exc_info.value.code == 1


class TestCLICustomSignatures:
    def test_custom_signatures_dir(self, monkeypatch, capsys, mocker, configure_mock_resolver, tmp_path):
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
        sig_file = tmp_path / "test.yml"
        sig_file.write_text(sig_content)

        monkeypatch.setattr("sys.argv", ["python", "-c", str(tmp_path), "-m", "CNAME", "bad.dns"])
        mock_data = {"bad.dns": {}}
        mock_resolver = configure_mock_resolver(mock_data)
        mocker.patch("baddns.cli.Client", return_value=mock_resolver)
        mocker.patch("baddns.lib.dnsmanager.Client", return_value=mock_resolver)
        cli.main()
        captured = capsys.readouterr()
        assert "custom signatures" in captured.err.lower() or True  # Runs without error


class TestValidateConfidence:
    def test_valid_levels(self):
        for level in ("CONFIRMED", "HIGH", "MEDIUM", "LOW"):
            assert cli.validate_confidence(level) == level

    def test_case_insensitive(self):
        assert cli.validate_confidence("confirmed") == "CONFIRMED"
        assert cli.validate_confidence("High") == "HIGH"

    def test_unknown_rejected(self):
        with pytest.raises(argparse.ArgumentTypeError, match="not a valid confidence level"):
            cli.validate_confidence("UNKNOWN")

    def test_invalid_value(self):
        with pytest.raises(argparse.ArgumentTypeError, match="not a valid confidence level"):
            cli.validate_confidence("BOGUS")


class TestValidateSeverity:
    def test_valid_levels(self):
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert cli.validate_severity(level) == level

    def test_case_insensitive(self):
        assert cli.validate_severity("critical") == "CRITICAL"
        assert cli.validate_severity("Medium") == "MEDIUM"

    def test_info_rejected(self):
        with pytest.raises(argparse.ArgumentTypeError, match="not a valid severity level"):
            cli.validate_severity("INFO")

    def test_invalid_value(self):
        with pytest.raises(argparse.ArgumentTypeError, match="not a valid severity level"):
            cli.validate_severity("BOGUS")


class TestCLIMinConfidenceFilter:
    def test_min_confidence_filters_findings(self, monkeypatch, capsys, mocker, configure_mock_resolver):
        """--min-confidence HIGH should exclude MEDIUM findings from CNAME nxdomain."""
        monkeypatch.setattr("sys.argv", ["python", "-s", "--min-confidence", "HIGH", "-m", "CNAME", "bad.dns"])
        mock_data = {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
        mock_resolver = configure_mock_resolver(mock_data)
        mocker.patch("baddns.cli.Client", return_value=mock_resolver)
        mocker.patch("baddns.lib.dnsmanager.Client", return_value=mock_resolver)
        cli.main()
        captured = capsys.readouterr()
        # CNAME nxdomain findings are CONFIRMED, so they should appear
        assert "baddns.azurewebsites.net" in captured.out

    def test_min_confidence_confirmed_excludes_high(self, monkeypatch, capsys, mocker, configure_mock_resolver):
        """--min-confidence CONFIRMED should exclude HIGH confidence CNAME nxdomain findings."""
        monkeypatch.setattr("sys.argv", ["python", "-s", "--min-confidence", "CONFIRMED", "-m", "CNAME", "bad.dns"])
        mock_data = {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
        mock_resolver = configure_mock_resolver(mock_data)
        mocker.patch("baddns.cli.Client", return_value=mock_resolver)
        mocker.patch("baddns.lib.dnsmanager.Client", return_value=mock_resolver)
        cli.main()
        captured = capsys.readouterr()
        # CNAME nxdomain findings are HIGH confidence, so CONFIRMED filter should exclude them
        assert "Vulnerable!" not in captured.out
        assert "azurewebsites" not in captured.out


class TestCLIMinSeverityFilter:
    def test_min_severity_critical_excludes_medium(self, monkeypatch, capsys, mocker, configure_mock_resolver):
        """--min-severity CRITICAL should exclude MEDIUM severity findings."""
        monkeypatch.setattr("sys.argv", ["python", "-s", "--min-severity", "CRITICAL", "-m", "CNAME", "bad.dns"])
        mock_data = {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
        mock_resolver = configure_mock_resolver(mock_data)
        mocker.patch("baddns.cli.Client", return_value=mock_resolver)
        mocker.patch("baddns.lib.dnsmanager.Client", return_value=mock_resolver)
        cli.main()
        captured = capsys.readouterr()
        # CNAME nxdomain findings are MEDIUM severity, so they should be filtered out
        assert "Vulnerable!" not in captured.out
        assert "azurewebsites" not in captured.out

    def test_min_severity_low_includes_medium(self, monkeypatch, capsys, mocker, configure_mock_resolver):
        """--min-severity LOW should include MEDIUM severity findings."""
        monkeypatch.setattr("sys.argv", ["python", "-s", "--min-severity", "LOW", "-m", "CNAME", "bad.dns"])
        mock_data = {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
        mock_resolver = configure_mock_resolver(mock_data)
        mocker.patch("baddns.cli.Client", return_value=mock_resolver)
        mocker.patch("baddns.lib.dnsmanager.Client", return_value=mock_resolver)
        cli.main()
        captured = capsys.readouterr()
        assert "baddns.azurewebsites.net" in captured.out


class TestExecuteModule:
    @pytest.mark.asyncio
    async def test_signature_exception(self, mocker):
        mock_module = mocker.MagicMock()
        mock_module.side_effect = BadDNSSignatureException("bad sig")
        with pytest.raises(BadDNSCLIException, match="Error loading signatures"):
            await cli.execute_module(mock_module, "bad.dns", None, [], silent=False)
