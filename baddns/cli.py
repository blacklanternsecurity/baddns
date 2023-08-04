#!/usr/bin/env python3
# baddns
# Black Lantern Security - https://www.blacklanternsecurity.com
# @paulmmueller

import re
import sys
import asyncio
import argparse
import pkg_resources

from colorama import Fore, Style, init

from .lib.baddns import BadDNS_cname

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


def validate_target(
    arg_value, pattern=re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$")
):
    if not pattern.match(arg_value):
        raise argparse.ArgumentTypeError(print_status("Target subdomain is not correctly formatted", color=Fore.RED))
    return arg_value


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

    parser.add_argument("target", type=validate_target, help="subdomain to analyze")

    args = parser.parse_args(unknown_args)

    if not args.target:
        parser.error(
            print_status(
                "A valid target (subdomain) is required",
                color=Fore.RED,
            )
        )
        return

    baddns_cname = BadDNS_cname(args.target)
    if await baddns_cname.dispatch():
        baddns_cname.analyze()
    else:
        print("No CNAME found, skipping rest of process")


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
