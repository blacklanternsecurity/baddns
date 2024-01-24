import ssl
import httpx

import logging
import httpx_cache

log = logging.getLogger(__name__)


class HttpManager:
    def __init__(self, target, http_client_class=None, skip_redirects=False):
        self.skip_redirects = skip_redirects
        if not http_client_class:
            http_client_class = httpx_cache.AsyncClient
        self.http_client = http_client_class(timeout=5, verify=False)
        self.target = target
        self.http_allowredirects_results = None
        self.http_denyredirects_results = None
        self.https_allowredirects_results = None
        self.https_denyredirects_results = None

    async def dispatchHttp(self):
        try:
            if self.skip_redirects == False:
                self.http_allowredirects_results = await self.http_client.get(
                    f"http://{self.target}/", follow_redirects=True
                )
                self.https_allowredirects_results = await self.http_client.get(
                    f"https://{self.target}/", follow_redirects=True
                )
            self.http_denyredirects_results = await self.http_client.get(
                f"http://{self.target}/", follow_redirects=False
            )
            self.https_denyredirects_results = await self.http_client.get(
                f"https://{self.target}/", follow_redirects=False
            )
        except httpx.RequestError as e:
            log.debug(f"An error occurred while requesting {e.request.url!r}: {e}")
        except httpx.ConnectError as e:
            log.debug(f"Http Connect Error {e.request.url!r}: {e}")
        except ssl.SSLError as e:
            log.debug(f"SSL Error: {e}")
