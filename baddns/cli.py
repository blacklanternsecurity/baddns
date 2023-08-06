#!/usr/bin/env python3
# baddns
# Black Lantern Security - https://www.blacklanternsecurity.com
# @paulmmueller

import re
import sys
import asyncio
import argparse
import logging
import pkg_resources

from .lib.baddns import BadDNS_cname

from colorama import Fore, Style, init

init(autoreset=True)  # Automatically reset the color to default after each print statement

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
    log = logging.getLogger()
    logging.getLogger("httpx").setLevel(logging.WARNING)
    log.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setFormatter(CustomLogFormatter())
    log.addHandler(ch)


def debug_logging(debug=False):
    log = logging.getLogger()
    if debug:
        log.setLevel(logging.DEBUG)


class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage()
        log.error(message)
        self.exit(1)


def print_version():
    version = pkg_resources.get_distribution("baddns").version
    if version == "0.0.0":
        version = "Unknown (Running w/poetry?)"
    print(f"Version - {version}\n")


def validate_target(
    arg_value, pattern=re.compile(r"^(?:[a-z0-9](?:[a-z0-9-_]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$")
):
    if not pattern.match(arg_value):
        raise argparse.ArgumentTypeError("Target subdomain is not correctly formatted")
    return arg_value


async def _main():
    setup_logging()
    parser = CustomArgumentParser(description="Check subdomains for subdomain takeovers and other DNS tomfoolery")
    print(f"{Fore.GREEN}{ascii_art_banner}{Style.RESET_ALL}")
    print_version()

    parser.add_argument("target", type=validate_target, help="subdomain to analyze")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    debug_logging(args.debug)

    baddns_cname = BadDNS_cname(args.target)
    if await baddns_cname.dispatch():
        finding = baddns_cname.analyze()
        if finding:
            print(f"{Fore.GREEN}{'Vulnerable!'}{Style.RESET_ALL}")
            print(finding)


def main():
    try:
        asyncio.run(_main())
    except asyncio.CancelledError:
        log.error("Got asyncio.CancelledError")

    except KeyboardInterrupt:
        sys.exit(1)


ascii_art_banner = """
  __ )              |      |              
  __ \    _` |   _` |   _` |  __ \    __| 
  |   |  (   |  (   |  (   |  |   | \__ \ 
 ____/  \__,_| \__,_| \__,_| _|  _| ____/ 
                                          
"""


if __name__ == "__main__":
    main()
