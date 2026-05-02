#!/usr/bin/env python3
"""
NullScan — Penetration Testing Recon Framework
Entry point: python3 nullscan.py [--help] [--tool N] [--target HOST]

Usage:
  Interactive:  python3 nullscan.py
  Direct:       python3 nullscan.py --tool 1 --target 8.8.8.8
"""

import sys
import time
import argparse

# ── Lazy imports so startup is instant ──
from modules.display import C, banner, menu, warn


def get_tools() -> dict:
    from modules.ip_lookup       import ip_lookup
    from modules.subdomain_enum  import subdomain_enum
    from modules.port_scanner    import port_scanner
    from modules.dns_recon       import dns_recon
    from modules.header_analyzer import header_analyzer
    from modules.reverse_ip      import reverse_ip
    from modules.auto_recon      import auto_recon
    from modules.report_viewer   import view_reports
    return {
        "1": ip_lookup,
        "2": subdomain_enum,
        "3": port_scanner,
        "4": dns_recon,
        "5": header_analyzer,
        "6": reverse_ip,
        "7": auto_recon,
        "8": view_reports,
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="NullScan — Penetration Testing Recon Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--tool", type=str, metavar="N",
        help="Run tool directly:\n"
             "  1 = IP Lookup\n  2 = Subdomain Enum\n  3 = Port Scanner\n"
             "  4 = DNS Recon\n  5 = Header Analyzer\n  6 = Reverse IP\n"
             "  7 = Auto Recon"
    )
    parser.add_argument("--target", type=str, metavar="HOST",
        help="Target IP/domain (used with --tool for non-interactive mode)"
    )
    return parser.parse_args()


def run_noninteractive(tool_id: str, target: str):
    """Run a tool directly with a pre-supplied target (no menu)."""
    import builtins
    original = builtins.input

    def patched_input(prompt=""):
        if any(kw in prompt.lower() for kw in ["host", "ip", "domain", "url"]):
            print(f"{prompt}{C.YELLOW}{target}{C.RESET}")
            return target
        if "choice" in prompt.lower():
            print(f"{prompt}{C.GRAY}1{C.RESET}")
            return "1"
        if "[y/n]" in prompt.lower():
            print(f"{prompt}{C.GRAY}n{C.RESET}")
            return "n"
        return original(prompt)

    tools = get_tools()
    if tool_id not in tools:
        warn(f"Unknown tool: {tool_id}")
        sys.exit(1)

    banner()
    builtins.input = patched_input
    try:
        tools[tool_id]()
    finally:
        builtins.input = original


def main():
    args = parse_args()

    # ── Non-interactive mode ──
    if args.tool and args.target:
        run_noninteractive(args.tool, args.target)
        return

    # ── Interactive loop ──
    tools = get_tools()
    while True:
        banner()
        menu()
        choice = input(f"  {C.BOLD}{C.WHITE}Enter choice:{C.RESET} ").strip()

        if choice == "0":
            print(f"\n  {C.GRAY}Exiting NullScan. Stay legal out there.{C.RESET}\n")
            sys.exit(0)

        if choice in tools:
            try:
                tools[choice]()
            except KeyboardInterrupt:
                print(f"\n\n  {C.YELLOW}Interrupted. Returning to menu...{C.RESET}")
            input(f"\n  {C.GRAY}Press Enter to return to menu...{C.RESET}")
        else:
            print(f"\n  {C.RED}Invalid choice.{C.RESET}")
            time.sleep(0.8)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.GRAY}Goodbye.{C.RESET}\n")
        sys.exit(0)
