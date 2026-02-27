import httpx
import logging
import asyncio

log = logging.getLogger(__name__)


async def as_completed(coros):
    tasks = {coro if isinstance(coro, asyncio.Task) else asyncio.create_task(coro): coro for coro in coros}
    while tasks:
        done, _ = await asyncio.wait(tasks.keys(), return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            tasks.pop(task)
            yield task


class HttpManager:
    def __init__(self, target, http_client_class=None, skip_redirects=False):
        self.skip_redirects = skip_redirects
        if not http_client_class:
            http_client_class = httpx.AsyncClient

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
        }

        self.http_client = http_client_class(timeout=5, verify=False, headers=headers)
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
                task = asyncio.create_task(self.http_client.get(base_url, follow_redirects=follow_redirects))
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
        """Clean up the http_client when done."""
        await self.http_client.aclose()
        log.debug("HTTP client closed successfully.")
