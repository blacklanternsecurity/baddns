"""Tests for TLS handshake-error detection, driving real blasthttp against a real socket.

The detection hinges on blasthttp surfacing the handshake alert, which it only does for requests that
skip its connection pool. Stubbing the client would hide that, so these tests use a genuine BlastHTTP
against a listener that replies to the ClientHello with the TLS alert we key off of.
"""

import socket
import ssl
import threading

import pytest
from blasthttp import BlastHTTP

from baddns.lib.httpmanager import HttpManager

# A TLS alert record: content type 22 (alert), TLS 1.2, fatal (2), description byte below.
INTERNAL_ERROR = 80
HANDSHAKE_FAILURE = 40


def _alert_record(description):
    return bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, description])


class AlertServer:
    """Listener that reads the ClientHello and answers with a fatal TLS alert, like an on-demand-TLS
    platform refusing a hostname it doesn't know."""

    def __init__(self, description=INTERNAL_ERROR):
        self.record = _alert_record(description)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.sni = []

    def __enter__(self):
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.sock.close()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(5)
            hello = conn.recv(8192)
            name = _parse_sni(hello)
            if name:
                self.sni.append(name)
            conn.sendall(self.record)
        except OSError:
            pass
        finally:
            conn.close()


def _parse_sni(data):
    """Pull the server_name extension out of a ClientHello, or None if it isn't there."""
    try:
        i = 5 + 4 + 2 + 32  # record header, handshake header, client version, random
        i += 1 + data[i]  # legacy session id
        i += 2 + int.from_bytes(data[i : i + 2], "big")  # cipher suites
        i += 1 + data[i]  # compression methods
        end = i + 2 + int.from_bytes(data[i : i + 2], "big")
        i += 2
        while i < end:
            ext_type = int.from_bytes(data[i : i + 2], "big")
            ext_len = int.from_bytes(data[i + 2 : i + 4], "big")
            if ext_type == 0:  # server_name: list header (2) + type (1) + name length (2)
                return data[i + 9 : i + 4 + ext_len].decode()
            i += 4 + ext_len
    except (IndexError, UnicodeDecodeError):
        return None
    return None


# A hostname with no DNS record anywhere; resolve_ip is what points it at the listener.
DANGLING = "dangling.tlsplatform.invalid"


@pytest.mark.asyncio
async def test_probe_tls_error_captures_real_handshake_alert():
    """The probe must surface the alert text that the *_tls.yml signatures match on."""
    with AlertServer() as server:
        manager = HttpManager(f"{DANGLING}:{server.port}", http_client=BlastHTTP())
        error = await manager.probe_tls_error(resolve_ip="127.0.0.1")

    assert error is not None, "probe returned no error for a refused handshake"
    assert error == manager.tls_error
    assert "tlsv1 alert internal error" in error
    # the signatures are scoped to a platform by CNAME, so the probe has to present that hostname
    assert server.sni == [DANGLING]


@pytest.mark.asyncio
async def test_probe_tls_error_distinguishes_a_different_alert():
    """An ordinary site refusing the handshake sends a different alert, which must not match."""
    with AlertServer(description=HANDSHAKE_FAILURE) as server:
        manager = HttpManager(f"{DANGLING}:{server.port}", http_client=BlastHTTP())
        error = await manager.probe_tls_error(resolve_ip="127.0.0.1")

    assert error is not None
    assert "tlsv1 alert internal error" not in error


@pytest.mark.asyncio
async def test_pooled_requests_do_not_carry_handshake_detail():
    """Why probe_tls_error exists: blasthttp's pooled path reports a generic connect error.

    If blasthttp ever starts including the handshake detail on the pooled path, this test fails and
    the probe can be dropped.
    """
    with AlertServer() as server:
        client = BlastHTTP()
        url = f"https://localhost:{server.port}/"
        with pytest.raises(Exception) as excinfo:
            await client.request(url, method="GET", timeout=5, verify_certs=False, follow_redirects=False)

    assert "TLS handshake failed" not in str(excinfo.value)


@pytest.mark.asyncio
async def test_probe_tls_error_skipped_when_https_succeeded():
    """No handshake problem means no reason to spend an extra request."""
    manager = HttpManager("example.com", http_client=BlastHTTP())
    manager.https_denyredirects_results = object()

    assert await manager.probe_tls_error(resolve_ip="127.0.0.1") is None
    assert manager.tls_error is None


@pytest.mark.asyncio
async def test_probe_tls_error_ignores_plain_connection_failure():
    """A closed port fails before any handshake; that is not a TLS refusal."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listening now

    manager = HttpManager(f"{DANGLING}:{port}", http_client=BlastHTTP())

    assert await manager.probe_tls_error(resolve_ip="127.0.0.1") is None
    assert manager.tls_error is None


def test_alert_server_sends_the_alert_openssl_recognizes():
    """Guards the handcrafted alert record: Python's own TLS stack must read it as alert 80."""
    with AlertServer() as server:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", server.port), timeout=5) as raw:
            with pytest.raises(ssl.SSLError) as excinfo:
                ctx.wrap_socket(raw, server_hostname=DANGLING)

    assert "tlsv1 alert internal error" in str(excinfo.value).lower()
