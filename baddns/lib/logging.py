import logging
from colorama import Fore, Style

log = None


class CustomLogFormatter(logging.Formatter):
    FORMATS = {
        logging.DEBUG: Fore.MAGENTA + "[%(levelname)s] %(message)s" + Style.RESET_ALL,
        logging.INFO: Fore.CYAN + "%(message)s" + Style.RESET_ALL,
        logging.WARNING: Fore.YELLOW + "[%(levelname)s] %(message)s" + Style.RESET_ALL,
        logging.ERROR: Fore.RED + "[%(levelname)s] %(message)s" + Style.RESET_ALL,
        logging.CRITICAL: Fore.RED + Style.BRIGHT + "[%(levelname)s] - %(message)s" + Style.RESET_ALL,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def setup_logging():
    global log
    log = logging.getLogger("baddns")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    log.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setFormatter(CustomLogFormatter())
    log.addHandler(ch)


def debug_logging(debug=False):
    global log
    log = logging.getLogger()
    if debug:
        log.setLevel(logging.DEBUG)
