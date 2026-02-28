import os
import sys
import dns
import pytest
from mock import patch

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(f"{os.path.dirname(SCRIPT_DIR)}")

from baddns import cli

import re


def _extract_filter_modules(stderr):
    """Extract module names from the 'Signature filter active' log line."""
    match = re.search(r"Signature filter active.*?\[([^\]]+)\]", stderr)
    if not match:
        return set()
    return {m.strip() for m in match.group(1).split(",")}


def _extract_all_modules(stderr):
    """Extract module names from the 'Running with all modules' log line."""
    match = re.search(r"Running with all modules \[([^\]]+)\]", stderr)
    if not match:
        return set()
    return {m.strip() for m in match.group(1).split(",")}


def test_cli_validation_target(monkeypatch, capsys):
    with patch("sys.exit") as exit_mock:
        monkeypatch.setattr("sys.argv", ["python"])
        cli.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        assert "the following arguments are required: target" in captured.err


def test_cli_validation_customnameservers_valid(monkeypatch, capsys):
    with patch("sys.exit") as exit_mock:
        monkeypatch.setattr("sys.argv", ["python", "-n", "1.1.1.1,8.8.8.8", "bad.dns"])
        cli.main()
        captured = capsys.readouterr()
        assert not exit_mock.called
        assert "custom nameservers: [1.1.1.1, 8.8.8.8]" in captured.err


def test_cli_validation_customnameservers_invalid(monkeypatch, capsys):
    with patch("sys.exit") as exit_mock:
        monkeypatch.setattr("sys.argv", ["python", "-n", "1.1.1.1 8.8.8.8", "bad.dns"])
        cli.main()
        captured = capsys.readouterr()
        print(captured.out)
        assert exit_mock.called
        assert "Nameservers argument is incorrectly formatted" in captured.err


def test_cli_cname_nxdomain(monkeypatch, capsys, mocker, configure_mock_resolver):
    monkeypatch.setattr(
        "sys.argv",
        ["python", "bad.dns", "-m", "CNAME"],
    )

    mock_data = {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data)
    mocker.patch.object(dns.asyncresolver, "Resolver", return_value=mock_resolver)

    cli.main()
    captured = capsys.readouterr()
    print(captured)
    assert "Vulnerable!" in captured.out
    assert "baddns.azurewebsites.net" in captured.out


@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
def test_cli_cname_http(monkeypatch, capsys, mocker, httpx_mock, configure_mock_resolver):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "-m",
            "CNAME",
            "bad.dns",
        ],
    )
    mock_data = {"bad.dns": {"CNAME": ["baddns.bigcartel.com"]}, "baddns.bigcartel.com": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    mocker.patch.object(dns.asyncresolver, "Resolver", return_value=mock_resolver)

    httpx_mock.add_response(
        url="http://bad.dns/",
        status_code=200,
        text="<h1>Oops! We couldn&#8217;t find that page.</h1>",
    )

    cli.main()
    captured = capsys.readouterr()
    assert "Vulnerable!" in captured.out
    assert "Bigcartel Takeover Detection" in captured.out


def test_cli_signature_filter_http_mode(monkeypatch, capsys, mocker, configure_mock_resolver):
    monkeypatch.setattr(
        "sys.argv",
        ["python", "-S", "dnsreaper_github_pages", "bad.dns"],
    )
    mock_data = {"bad.dns": {"CNAME": ["baddns.example.com."]}, "_NXDOMAIN": ["baddns.example.com"]}
    mock_resolver = configure_mock_resolver(mock_data)
    mocker.patch.object(dns.asyncresolver, "Resolver", return_value=mock_resolver)

    cli.main()
    captured = capsys.readouterr()
    assert "Signature filter active" in captured.err
    active_modules = _extract_filter_modules(captured.err)
    assert "CNAME" in active_modules
    assert "references" in active_modules
    assert "TXT" in active_modules
    for excluded in ["NS", "MX", "NSEC", "zonetransfer"]:
        assert excluded not in active_modules


def test_cli_signature_filter_nosoa_mode(monkeypatch, capsys, mocker, configure_mock_resolver):
    monkeypatch.setattr(
        "sys.argv",
        ["python", "-S", "dnsreaper_aws_ns", "bad.dns"],
    )
    mock_data = {"bad.dns": {"CNAME": ["baddns.example.com."]}, "_NXDOMAIN": ["baddns.example.com"]}
    mock_resolver = configure_mock_resolver(mock_data)
    mocker.patch.object(dns.asyncresolver, "Resolver", return_value=mock_resolver)

    cli.main()
    captured = capsys.readouterr()
    assert "Signature filter active" in captured.err
    active_modules = _extract_filter_modules(captured.err)
    assert "NS" in active_modules
    for excluded in ["CNAME", "TXT", "references"]:
        assert excluded not in active_modules


def test_cli_signature_filter_mixed_modes(monkeypatch, capsys, mocker, configure_mock_resolver):
    monkeypatch.setattr(
        "sys.argv",
        ["python", "-S", "dnsreaper_github_pages,dnsreaper_aws_ns", "bad.dns"],
    )
    mock_data = {"bad.dns": {"CNAME": ["baddns.example.com."]}, "_NXDOMAIN": ["baddns.example.com"]}
    mock_resolver = configure_mock_resolver(mock_data)
    mocker.patch.object(dns.asyncresolver, "Resolver", return_value=mock_resolver)

    cli.main()
    captured = capsys.readouterr()
    assert "Signature filter active" in captured.err
    active_modules = _extract_filter_modules(captured.err)
    assert "CNAME" in active_modules
    assert "NS" in active_modules
    assert "references" in active_modules
    assert "TXT" in active_modules


def test_cli_no_signature_filter_runs_all(monkeypatch, capsys, mocker, configure_mock_resolver):
    monkeypatch.setattr(
        "sys.argv",
        ["python", "bad.dns"],
    )
    mock_data = {"bad.dns": {"CNAME": ["baddns.example.com."]}, "_NXDOMAIN": ["baddns.example.com"]}
    mock_resolver = configure_mock_resolver(mock_data)
    mocker.patch.object(dns.asyncresolver, "Resolver", return_value=mock_resolver)

    cli.main()
    captured = capsys.readouterr()
    assert "Running with all modules" in captured.err
    assert "Signature filter active" not in captured.err
    all_modules = _extract_all_modules(captured.err)
    for module_name in ["CNAME", "NS", "MX", "NSEC", "zonetransfer", "TXT", "references"]:
        assert module_name in all_modules


def test_cli_signature_filter_with_module_flag(monkeypatch, capsys, mocker, configure_mock_resolver):
    monkeypatch.setattr(
        "sys.argv",
        ["python", "-S", "dnsreaper_github_pages", "-m", "CNAME", "bad.dns"],
    )
    mock_data = {"bad.dns": {"CNAME": ["baddns.example.com."]}, "_NXDOMAIN": ["baddns.example.com"]}
    mock_resolver = configure_mock_resolver(mock_data)
    mocker.patch.object(dns.asyncresolver, "Resolver", return_value=mock_resolver)

    cli.main()
    captured = capsys.readouterr()
    assert "Signature filter active" in captured.err
    active_modules = _extract_filter_modules(captured.err)
    assert active_modules == {"CNAME"}


def test_cli_signature_filter_nxdomain_integration(monkeypatch, capsys, mocker, configure_mock_resolver):
    monkeypatch.setattr(
        "sys.argv",
        ["python", "-S", "nucleitemplates_azure-takeover-detection", "-m", "CNAME", "bad.dns"],
    )
    mock_data = {"bad.dns": {"CNAME": ["baddns.azurewebsites.net."]}, "_NXDOMAIN": ["baddns.azurewebsites.net"]}
    mock_resolver = configure_mock_resolver(mock_data)
    mocker.patch.object(dns.asyncresolver, "Resolver", return_value=mock_resolver)

    cli.main()
    captured = capsys.readouterr()
    assert "Vulnerable!" in captured.out
    assert "Azure" in captured.out


def test_cli_list_signatures(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["python", "-L"])
    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "Available Signatures:" in captured.out
    assert "dnsreaper_github_pages" in captured.out


def test_cli_signature_filter_silent_mode(monkeypatch, capsys, mocker, configure_mock_resolver):
    monkeypatch.setattr(
        "sys.argv",
        ["python", "-s", "-S", "dnsreaper_github_pages", "bad.dns"],
    )
    mock_data = {"bad.dns": {"CNAME": ["baddns.example.com."]}, "_NXDOMAIN": ["baddns.example.com"]}
    mock_resolver = configure_mock_resolver(mock_data)
    mocker.patch.object(dns.asyncresolver, "Resolver", return_value=mock_resolver)

    cli.main()
    captured = capsys.readouterr()
    assert "Signature filter active" not in captured.err
    assert "baddns" not in captured.out.split("{")[0] if "{" in captured.out else True


@pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
def test_cli_direct(monkeypatch, capsys, mocker, httpx_mock, configure_mock_resolver):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "--direct",
            "bad.dns",
        ],
    )
    mock_data = {"bad.dns": {"A": ["127.0.0.1"]}}
    mock_resolver = configure_mock_resolver(mock_data)
    mocker.patch.object(dns.asyncresolver, "Resolver", return_value=mock_resolver)

    httpx_mock.add_response(
        url="http://bad.dns/",
        status_code=200,
        text="The specified bucket does not exist",
    )

    cli.main()
    captured = capsys.readouterr()
    assert "Direct mode specified. Only the CNAME module is enabled" in captured.err
    assert "Vulnerable!" in captured.out
    assert "AWS Bucket Takeover Detection" in captured.out
