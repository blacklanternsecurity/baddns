import logging
from baddns.lib.logging import setup_logging, debug_logging, CustomLogFormatter


class TestSetupLogging:
    def test_setup_logging(self):
        setup_logging()
        log = logging.getLogger("baddns")
        assert log.level == logging.INFO
        assert any(isinstance(h.formatter, CustomLogFormatter) for h in log.handlers)

    def test_httpx_log_level(self):
        setup_logging()
        httpx_log = logging.getLogger("httpx")
        assert httpx_log.level == logging.WARNING


class TestDebugLogging:
    def test_debug_enabled(self):
        debug_logging(debug=True)
        log = logging.getLogger()
        assert log.level == logging.DEBUG

    def test_debug_disabled(self):
        debug_logging(debug=False)
        # When debug=False, no change is made (function body only runs when debug=True)


class TestCustomLogFormatter:
    def test_format_info(self):
        formatter = CustomLogFormatter()
        record = logging.LogRecord("test", logging.INFO, "", 0, "test message", (), None)
        formatted = formatter.format(record)
        assert "test message" in formatted

    def test_format_debug(self):
        formatter = CustomLogFormatter()
        record = logging.LogRecord("test", logging.DEBUG, "", 0, "debug msg", (), None)
        formatted = formatter.format(record)
        assert "debug msg" in formatted

    def test_format_warning(self):
        formatter = CustomLogFormatter()
        record = logging.LogRecord("test", logging.WARNING, "", 0, "warn msg", (), None)
        formatted = formatter.format(record)
        assert "warn msg" in formatted

    def test_format_error(self):
        formatter = CustomLogFormatter()
        record = logging.LogRecord("test", logging.ERROR, "", 0, "error msg", (), None)
        formatted = formatter.format(record)
        assert "error msg" in formatted

    def test_format_critical(self):
        formatter = CustomLogFormatter()
        record = logging.LogRecord("test", logging.CRITICAL, "", 0, "critical msg", (), None)
        formatted = formatter.format(record)
        assert "critical msg" in formatted
