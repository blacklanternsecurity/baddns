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

from .lib.errors import BadDNSSignatureException, BadDNSCLIException
from .lib.logging import setup_logging
from .lib.loader import load_signatures

from baddns.base import get_all_modules


from colorama import Fore, Style, init

init(autoreset=True)  # Automatically reset the color to default after each print statement

modules = get_all_modules()


class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage()
        log.error(message)
        raise BadDNSCLIException(message)


def print_version():
    version = pkg_resources.get_distribution("baddns").version
    if version == "1.0.0":
        version = "Unknown (Running w/poetry?)"
    print(f"Version - {version}\n")


def validate_target(
    arg_value, pattern=re.compile(r"^(?:[a-z0-9_](?:[a-z0-9-_]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$")
):
    if not pattern.match(arg_value):
        raise argparse.ArgumentTypeError("Target subdomain is not correctly formatted")
    return arg_value


def validate_nameservers(
    arg_value,
    pattern=re.compile(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(,((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))*$"
    ),
):
    if not pattern.match(arg_value):
        raise argparse.ArgumentTypeError("Nameservers argument is incorrectly formatted")
    return arg_value


def validate_modules(arg_value, pattern=re.compile(r"^[a-zA-Z0-9_]+(,[a-zA-Z0-9_]+)*$")):
    if not pattern.match(arg_value):
        raise argparse.ArgumentTypeError(
            "The format of provided modules is incorrect. Use comma-separated values without spaces."
        )

    modules_provided = [m.upper() for m in arg_value.split(",")]
    for m in modules_provided:
        if not any(m in module.name.upper() for module in modules):
            raise argparse.ArgumentTypeError(
                f"'{m}' is not a recognized module. Please check the module name or use '-l' to list available modules."
            )
    return arg_value


async def execute_module(ModuleClass, target, custom_nameservers, signatures):
    findings = None
    try:
        module_instance = ModuleClass(target, custom_nameservers=custom_nameservers, signatures=signatures, cli=True)
    except BadDNSSignatureException as e:
        log.error(f"Error loading signatures: {e}")
        raise BadDNSCLIException(f"Error loading signatures: {e}")

    log.info(f"Starting [{module_instance.name}] module with target [{target}]")
    if await module_instance.dispatch():
        findings = module_instance.analyze()
        if findings:
            print(f"{Fore.GREEN}{'Vulnerable!'}{Style.RESET_ALL}")
            for finding in findings:
                print(finding.to_dict())
    return findings


async def _main():
    setup_logging()
    global log
    log = logging.getLogger("baddns")

    parser = CustomArgumentParser(description="Check subdomains for subdomain takeovers and other DNS tomfoolery")
    print(f"{Fore.GREEN}{ascii_art_banner}{Style.RESET_ALL}")
    print_version()

    parser.add_argument(
        "-n",
        "--custom-nameservers",
        type=validate_nameservers,
        help="Provide a list of custom nameservers separated by comma.",
    )

    parser.add_argument(
        "-c",
        "--custom-signatures",
        help="Use an alternate directory for loading signatures",
    )

    parser.add_argument(
        "-l", "--list-modules", action="store_true", help="List available modules and their descriptions."
    )

    parser.add_argument(
        "-m",
        "--modules",
        type=validate_modules,
        help="Comma separated list of module names to use. Ex: module1,module2,module3",
    )

    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging")

    parser.add_argument("target", nargs="?", type=validate_target, help="subdomain to analyze")
    args = parser.parse_args()

    if not args.target and not args.list_modules:
        parser.error("the following arguments are required: target")

    if args.list_modules:
        r = get_all_modules()
        print("Available Modules:")
        for m in r:
            log.info(f"[{m.name}] - {m.description}")
        sys.exit(0)

    if args.debug:
        log.setLevel(logging.DEBUG)

    # Get all available modules
    all_modules = get_all_modules()

    # If the user provided the -m or --modules argument, filter the modules accordingly
    if args.modules:
        included_module_names = [name.strip().upper() for name in args.modules.split(",")]
        modules_to_execute = [module for module in all_modules if module.name.upper() in included_module_names]
    else:
        modules_to_execute = all_modules  # Default to all modules if -m is not provided
        log.info(
            f"Running with all modules [{', '.join([module.name for module in modules_to_execute])}] (-m to specify)"
        )

    custom_signatures = None
    if args.custom_signatures:
        custom_signatures = args.custom_signatures
        log.info(f"Using custom signatures directory: [{args.custom_signatures}]")

    custom_nameservers = None
    if args.custom_nameservers:
        custom_nameservers = args.custom_nameservers.split(",")
        log.info(f"Using custom nameservers: [{', '.join(custom_nameservers)}]")

    signatures = load_signatures(signatures_dir=custom_signatures)

    for ModuleClass in modules_to_execute:
        await execute_module(ModuleClass, args.target, custom_nameservers, signatures)


def main():
    try:
        asyncio.run(_main())
    except asyncio.CancelledError:
        log.error("Got asyncio.CancelledError")

    except BadDNSCLIException:
        sys.exit(1)

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
