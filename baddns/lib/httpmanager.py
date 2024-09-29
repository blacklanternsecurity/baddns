import httpx
import logging
import asyncio

log = logging.getLogger(__name__)


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
        tasks = []

        for protocol in protocols:
            base_url = f"{protocol}://{self.target}/"
            log.debug(f"ready to make request to URL: {base_url}")

            follow_redirects_options = [True, False] if not self.skip_redirects else [False]

            for follow_redirects in follow_redirects_options:
                tasks.append((self.http_client.get(base_url, follow_redirects=follow_redirects), base_url))

        # Execute all requests concurrently, and ensure that exceptions don't derail the entire run
        results = await asyncio.gather(*(task for task, _ in tasks), return_exceptions=True)

        # Store the results back into the object, handling any exceptions
        idx = 0
        for protocol in protocols:
            # Handle the allow_redirects case
            if not self.skip_redirects:
                result = results[idx]
                url = tasks[idx][1]  # Get the URL associated with this task
                if isinstance(result, Exception):
                    log.debug(f"Error occurred while fetching {url} (allow redirects): {result}")
                    setattr(self, f"{protocol}_allowredirects_results", None)
                else:
                    setattr(self, f"{protocol}_allowredirects_results", result)
                idx += 1

            # Handle the deny_redirects case
            result = results[idx]
            url = tasks[idx][1]  # Get the URL associated with this task
            if isinstance(result, Exception):
                log.debug(f"Error occurred while fetching {url} (deny redirects): {result}")
                setattr(self, f"{protocol}_denyredirects_results", None)
            else:
                setattr(self, f"{protocol}_denyredirects_results", result)
            idx += 1
