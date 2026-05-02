"""
auto_recon.py — Full automated recon: chains IP Lookup + Port Scan + DNS + Headers
"""

from modules.display import C, divider, warn, info, section
from modules.ip_lookup      import ip_lookup      as _ip
from modules.port_scanner   import port_scanner   as _ports
from modules.dns_recon      import dns_recon      as _dns
from modules.header_analyzer import header_analyzer as _headers


def auto_recon():
    section("FULL AUTO RECON")
    print(f"  {C.GRAY}This runs: IP Lookup → Port Scan → DNS Recon → Header Analysis{C.RESET}")
    print(f"  {C.GRAY}Each tool will save its own report.{C.RESET}\n")

    target = input(f"  {C.CYAN}Enter target domain or IP:{C.RESET} ").strip()
    if not target:
        warn("No input provided.")
        return

    print(f"\n  {C.GREEN}Starting full recon on:{C.RESET} {C.YELLOW}{target}{C.RESET}\n")
    print(f"  {'─'*48}\n")

    # Step 1: IP Lookup
    divider(f"STEP 1/4 — IP LOOKUP")
    _ip()   # has its own input prompt — we run inline

    # Steps 2–4 are run with the same target passed implicitly
    # Since each module prompts for input, we monkey-patch input for automation
    import builtins
    original_input = builtins.input

    def auto_input(prompt=""):
        # Intercept the first domain/IP input in each module
        if any(kw in prompt.lower() for kw in ["host", "ip", "domain", "url"]):
            print(f"{prompt}{C.YELLOW}{target}{C.RESET}")
            return target
        # For sub-prompts (scan type, banners, etc.) — use sensible defaults
        if "choice" in prompt.lower():
            print(f"{prompt}{C.GRAY}1{C.RESET}")
            return "1"
        if "[y/n]" in prompt.lower():
            print(f"{prompt}{C.GRAY}n{C.RESET}")
            return "n"
        return original_input(prompt)

    builtins.input = auto_input

    try:
        divider(f"STEP 2/4 — PORT SCAN")
        _ports()

        divider(f"STEP 3/4 — DNS RECON")
        _dns()

        divider(f"STEP 4/4 — HEADER ANALYSIS")
        _headers()
    finally:
        builtins.input = original_input

    divider("AUTO RECON COMPLETE")
    info(f"All reports saved to {C.WHITE}output/{C.RESET}")
    print()
