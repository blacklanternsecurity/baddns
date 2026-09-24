import logging
import asyncio

from blasthttp import BlastHTTP

log = logging.getLogger(__name__)


USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0"


def header_items(headers):
    """Return headers as a list of (name, value) pairs, keeping duplicates.

    Accepts blasthttp's ``Headers`` object (iterating it yields names only; ``.items()`` yields pairs),
    a dict, or an iterable of (name, value) tuples.
    """
    if headers is None:
        return []
    if hasattr(headers, "items"):
        return list(headers.items())
    return list(headers)


def headers_to_dict(headers):
    """Normalize a blasthttp-style header iterable (list of (k, v) tuples) to a dict.

    Duplicate keys collapse to the last value.
    """
    if isinstance(headers, dict):
        return headers
    return dict(headers or [])


async def as_completed(coros):
    tasks = {coro if isinstance(coro, asyncio.Future) else asyncio.ensure_future(coro): coro for coro in coros}
    while tasks:
        done, _ = await asyncio.wait(tasks.keys(), return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            tasks.pop(task)
            yield task


class HttpManager:
    def __init__(self, target, http_client=None, skip_redirects=False):
        self.skip_redirects = skip_redirects
        self.http_client = http_client if http_client is not None else BlastHTTP()
        self.target = target
        for attr in [
            "http_allowredirects_results",
            "http_denyredirects_results",
            "https_allowredirects_results",
            "https_denyredirects_results",
        ]:
            setattr(self, attr, None)

    async def dispatchHttp(self):
        protocols = ["http", "https"]
        tasks = {}

        # Create tasks for both protocols (http and https) and both follow_redirects options
        for protocol in protocols:
            base_url = f"{protocol}://{self.target}/"
            log.debug(f"Ready to make request to URL: {base_url}")

            follow_redirects_options = [True, False] if not self.skip_redirects else [False]
            for follow_redirects in follow_redirects_options:
                # ensure_future (not create_task) — blasthttp's pyo3-backed
                # request returns a Future, not a coroutine.
                task = asyncio.ensure_future(
                    self.http_client.request(
                        base_url,
                        method="GET",
                        headers=[("User-Agent", USER_AGENT)],
                        timeout=5,
                        verify_certs=False,
                        follow_redirects=follow_redirects,
                    )
                )
                tasks[task] = (protocol, follow_redirects, base_url)

        # Use as_completed to handle each task as it completes
        async for completed_task in as_completed(tasks):
            protocol, follow_redirects, base_url = tasks[completed_task]

            attr_suffix = "allowredirects_results" if follow_redirects else "denyredirects_results"
            attr_name = f"{protocol}_{attr_suffix}"

            try:
                response = await completed_task
                setattr(self, attr_name, response)
            except Exception as e:
                log.debug(f"Error occurred while fetching {base_url} (follow_redirects={follow_redirects}): {e}")
                setattr(self, attr_name, None)

    async def close(self):
        """No-op. blasthttp clients are shared and don't need per-consumer teardown."""
        pass
