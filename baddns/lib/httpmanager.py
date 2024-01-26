import ssl
import anyio
import httpx
import logging
import httpx_cache

log = logging.getLogger(__name__)


class HttpManager:
    urls_to_try = ["http://{target}/", "https://{target}/"]

    def __init__(self, target, http_client_class=None, skip_redirects=False):
        self.skip_redirects = skip_redirects
        if not http_client_class:
            http_client_class = httpx_cache.AsyncClient
        self.http_client = http_client_class(timeout=5, verify=False)
        self.target = target
        self.results = {}

    async def dispatchHttp(self):
        try:
            for url in self.urls_to_try:
                self.results[url] = await self.http_client.get(
                    url.format(target=self.target), follow_redirects=(not self.skip_redirects)
                )
        except (httpx.RequestError, httpx.ConnectError, httpx.TimeoutException) as e:
            log.debug(f"An httpx error occurred while requesting {e.request.url!r}: {e}")
        except ssl.SSLError as e:
            log.debug(f"An ssl error occurred while requesting {e.request.url!r}: {e}")
        except anyio.EndOfStream as e:
            log.debug(f"An anyio error occurred while requesting {e.request.url!r}: {e}")
