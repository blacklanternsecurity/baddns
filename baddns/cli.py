#!/usr/bin/env python3
# baddns
# Black Lantern Security - https://www.blacklanternsecurity.com
# @paulmmueller

import os
import asyncio
import argparse
import pkg_resources

from colorama import Fore, Style, init

from .lib.baddns import BadDNS

init(autoreset=True)  # Automatically reset the color to default after each print statement


class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage()
        self.exit(1)


def print_version():
    version = pkg_resources.get_distribution("baddns").version
    if version == "0.0.0":
        version = "Version Unknown (Running w/poetry?)"
    print(f"v{version}\n")


def print_status(msg, passthru=False, color=Fore.WHITE):
    if msg:
        if colorenabled:
            msg = f"{color}{msg}{Style.RESET_ALL}"
        if passthru:
            return msg
        else:
            print(msg)


async def _main():
    global colorenabled
    colorenabled = False
    color_parser = argparse.ArgumentParser(add_help=False)

    color_parser.add_argument(
        "-nc",
        "--no-color",
        action="store_true",
        help="Disable color message in the console",
    )

    args, unknown_args = color_parser.parse_known_args()
    colorenabled = not args.no_color

    parser = CustomArgumentParser(
        description="Check subdomains for subdomain takeovers and other DNS tomfoolery", parents=[color_parser]
    )

    if colorenabled:
        print_status(ascii_art_banner, color=Fore.GREEN)

    else:
        print(ascii_art_banner)
    print_version()

    parser.add_argument("target", nargs="*", type=str, help="subdomain to analyze")

    args = parser.parse_args(unknown_args)
    print("let there be baddns")

    baddns = BadDNS(args.target)
    baddns.check()


def main():
    try:
        asyncio.run(_main())
    except asyncio.CancelledError:
        print_status("Got asyncio.CancelledError", "red")

    except KeyboardInterrupt:
        sys.exit(1)


ascii_art_banner = """
  |                 |      |              
  __ \    _` |   _` |   _` |  __ \    __| 
  |   |  (   |  (   |  (   |  |   | \__ \ 
 _.__/  \__,_| \__,_| \__,_| _|  _| ____/ 
"""


if __name__ == "__main__":
    main()
