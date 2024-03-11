import ssl
import anyio
import httpx
import logging

log = logging.getLogger(__name__)


class HttpManager:
    def __init__(self, target, http_client_class=None, skip_redirects=False):
        self.skip_redirects = skip_redirects
        if not http_client_class:
            http_client_class = httpx.AsyncClient
        self.http_client = http_client_class(timeout=5, verify=False)
        self.target = target
        for attr in [
            "http_allowredirects_results",
            "http_denyredirects_results",
            "https_allowredirects_results",
            "https_denyredirects_results",
        ]:
            setattr(self, attr, None)

    async def dispatchHttp(self):
        try:
            protocols = ["http", "https"]
            for protocol in protocols:
                base_url = f"{protocol}://{self.target}/"
                # If redirects are not skipped by this module, perform requests that follow redirects
                if not self.skip_redirects:
                    setattr(
                        self,
                        f"{protocol}_allowredirects_results",
                        await self.http_client.get(base_url, follow_redirects=True),
                    )
                # Always perform requests that do not follow redirects
                setattr(
                    self,
                    f"{protocol}_denyredirects_results",
                    await self.http_client.get(base_url, follow_redirects=False),
                )
        except (httpx.RequestError, httpx.ConnectError, httpx.TimeoutException) as e:
            log.debug(f"An httpx error occurred while requesting {e.request.url!r}: {e}")
        except ssl.SSLError as e:
            log.debug(f"An SSL error occurred while requesting {e}")
        except anyio.EndOfStream as e:
            log.debug(f"An anyio error occurred while requesting {e}")
