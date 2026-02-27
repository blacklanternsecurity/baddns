import pytest
from unittest.mock import patch
from whois.exceptions import PywhoisError
from baddns.lib.whoismanager import WhoisManager


class TestWhoisManager:
    """Test WhoisManager error handling, specifically PywhoisError"""

    def setup_method(self):
        WhoisManager.clear_cache()

    @pytest.mark.asyncio
    async def test_pywhois_error_handling(self):
        """Test that PywhoisError is properly caught and handled"""
        manager = WhoisManager("nonexistentdomain123456789.com")

        with patch("whois.whois") as mock_whois:
            mock_whois.side_effect = PywhoisError("No match for domain")

            await manager.dispatchWHOIS()

            # Verify the error was caught and stored
            assert manager.whois_result["type"] == "error"
            assert "No match for domain" in str(manager.whois_result["data"])

            # Test analyzeWHOIS detects "unregistered"
            findings = manager.analyzeWHOIS()
            assert findings == ["unregistered"]

    @pytest.mark.asyncio
    async def test_invalid_domain_handling(self):
        """Test handling of invalid domains that don't pass validation"""
        manager = WhoisManager("invalid-domain-format")
        await manager.dispatchWHOIS()

        assert manager.whois_result["type"] == "error"
        assert manager.whois_result["data"] == "Invalid domain for WHOIS"

    @pytest.mark.asyncio
    async def test_successful_whois_query(self):
        """Test successful WHOIS query doesn't trigger errors"""
        manager = WhoisManager("example.com")

        mock_whois_data = {
            "domain_name": "example.com",
            "registrar": "Test Registrar",
            "expiration_date": "2025-12-31",
        }

        with patch("whois.whois") as mock_whois:
            mock_whois.return_value = mock_whois_data
            await manager.dispatchWHOIS()

            assert manager.whois_result["type"] == "response"
            assert manager.whois_result["data"] == mock_whois_data
