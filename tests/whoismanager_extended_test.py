import pytest
from unittest.mock import patch
from datetime import datetime, timezone, timedelta
from baddns.lib.whoismanager import WhoisManager


class TestDispatchWHOIS:
    @pytest.mark.asyncio
    async def test_generic_exception(self):
        manager = WhoisManager("example.com")
        with patch("whois.whois") as mock_whois:
            mock_whois.side_effect = RuntimeError("connection failed")
            await manager.dispatchWHOIS()
            assert manager.whois_result["type"] == "error"
            assert "connection failed" in manager.whois_result["data"]

    @pytest.mark.asyncio
    async def test_empty_registered_domain(self):
        manager = WhoisManager("com")
        await manager.dispatchWHOIS()
        # "com" has no dot, should be caught by guard
        assert manager.whois_result["type"] == "error"


class TestAnalyzeWHOIS:
    def test_none_whois_result(self):
        manager = WhoisManager("example.com")
        manager.whois_result = None
        result = manager.analyzeWHOIS()
        assert result is None

    def test_not_expired(self):
        future_date = datetime.now(timezone.utc) + timedelta(days=365)
        manager = WhoisManager("example.com")
        manager.whois_result = {"type": "response", "data": {"expiration_date": future_date}}
        findings = manager.analyzeWHOIS()
        assert findings == []

    def test_multiple_expiration_dates(self):
        old_date = datetime(2020, 1, 1, tzinfo=timezone.utc)
        older_date = datetime(2019, 1, 1, tzinfo=timezone.utc)
        manager = WhoisManager("example.com")
        manager.whois_result = {"type": "response", "data": {"expiration_date": [old_date, older_date]}}
        findings = manager.analyzeWHOIS()
        assert any("Registration Expired" in f for f in findings)

    def test_multiple_expiration_dates_not_expired(self):
        future = datetime.now(timezone.utc) + timedelta(days=365)
        manager = WhoisManager("example.com")
        manager.whois_result = {"type": "response", "data": {"expiration_date": [future, future]}}
        findings = manager.analyzeWHOIS()
        assert findings == []

    def test_error_without_no_match(self):
        manager = WhoisManager("example.com")
        manager.whois_result = {"type": "error", "data": "Some random error"}
        findings = manager.analyzeWHOIS()
        assert findings == []


class TestDateParse:
    def test_datetime_passthrough(self):
        dt = datetime(2024, 1, 1)
        assert WhoisManager.date_parse(dt) == dt

    def test_string_parsing(self):
        result = WhoisManager.date_parse("2024-01-15")
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15

    def test_invalid_string(self):
        result = WhoisManager.date_parse("not-a-date-at-all-xyzzy")
        assert result is None

    def test_unsupported_type(self):
        result = WhoisManager.date_parse(12345)
        assert result is None


class TestNormalizeDate:
    def test_naive_datetime(self):
        dt = datetime(2024, 1, 1)
        normalized = WhoisManager.normalize_date(dt)
        assert normalized.tzinfo == timezone.utc

    def test_aware_datetime(self):
        dt = datetime(2024, 1, 1, tzinfo=timezone(timedelta(hours=5)))
        normalized = WhoisManager.normalize_date(dt)
        assert normalized.tzinfo == timezone.utc
