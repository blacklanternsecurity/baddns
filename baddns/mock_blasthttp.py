"""
Minimal in-process mock for blasthttp's ``BlastHTTP`` client, for baddns tests.

Usage:
    mock = MockBlastHTTP()
    mock.add_response(url="http://example.com/", status=200, body="hello")

    module = BadDNS_cname("example.com", http_client=mock, ...)
    await module.dispatch()

Only ``add_response`` is supported (baddns tests don't need callbacks, streaming,
or header/body matching). URLs match exactly as passed, with trailing-slash
normalization.
"""

from collections import deque


def _normalize(url):
    return url.rstrip("/") if url else url


class MockHeaders:
    """Mirrors blasthttp's ``Headers``: iterating yields names; ``items()`` yields (name, value) pairs incl. duplicates."""

    def __init__(self, pairs):
        self._pairs = list(pairs)

    def items(self):
        return list(self._pairs)

    def keys(self):
        return [k for k, _ in self._pairs]

    def values(self):
        return [v for _, v in self._pairs]

    def get(self, name, default=None):
        for k, v in reversed(self._pairs):
            if k.lower() == name.lower():
                return v
        return default

    def __getitem__(self, name):
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return len(self._pairs)


class MockResponse:
    """Minimal shim matching the attributes baddns reads off blasthttp.Response."""

    def __init__(self, status=200, body="", headers=None, url=""):
        self.status = status
        self.body = body if isinstance(body, str) else body.decode("utf-8", errors="replace")
        self.body_bytes = body.encode() if isinstance(body, str) else body
        pairs = (headers or {}).items() if isinstance(headers, dict) else (headers or [])
        self.headers = MockHeaders(pairs)
        self.url = url
        self.elapsed_ms = 0
        self.redirect_chain = []
        self.cert_info = None


class MockBlastHTTP:
    """Drop-in replacement for ``blasthttp.BlastHTTP`` in tests.

    Register per-URL responses with ``add_response``. Unregistered URLs raise
    a ``RuntimeError`` so tests fail loudly instead of silently producing no-op
    responses.
    """

    def __init__(self):
        # url (normalized) -> deque of MockResponse (supports multiple calls)
        self._responses = {}

    def add_response(self, url="", status=200, body="", headers=None):
        key = _normalize(url)
        resp = MockResponse(status=status, body=body, headers=headers, url=url)
        self._responses.setdefault(key, deque()).append(resp)

    async def request(self, url, method="GET", **kwargs):
        key = _normalize(url)
        queue = self._responses.get(key)
        if not queue:
            raise RuntimeError(f"MockBlastHTTP: no response registered for {method} {url}")
        if len(queue) == 1:
            return queue[0]
        return queue.popleft()
