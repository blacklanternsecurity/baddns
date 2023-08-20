import os
import sys
import dns
from mock import patch

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(f"{os.path.dirname(SCRIPT_DIR)}")

from baddns import cli


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
    mock_data = {"bad.dns": {"CNAME": ["baddns.bigcartel.com"]}, "baddns.bigcartel.com": {"A": "127.0.0.1"}}
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
