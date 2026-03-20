import pytest
from baddns.base import BadDNS_base


@pytest.mark.asyncio
async def test_base_dispatch_not_implemented():
    base = BadDNS_base("example.com")
    with pytest.raises(NotImplementedError):
        await base._dispatch()
