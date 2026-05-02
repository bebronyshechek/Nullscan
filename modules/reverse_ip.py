"""
reverse_ip.py — Reverse IP lookup: find other domains hosted on same IP
Uses HackerTarget API (free tier: 500 req/day)
"""

import urllib.request
import urllib.error
import socket

from modules.display import C, divider, ok, warn, info, section
from modules.reporter import save_report


def _hackertarget_reverse(ip: str) -> list[str]:
    url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    try:
        req = urllib.request.urlopen(url, timeout=10)
        body = req.read().decode().strip()
        if "error" in body.lower() or "API count" in body:
            warn(f"HackerTarget: {body}")
            return []
        return [line.strip() for line in body.splitlines() if line.strip()]
    except Exception as e:
        warn(f"HackerTarget error: {e}")
        return []


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def reverse_ip():
    section("REVERSE IP LOOKUP")
    target = input(f"  {C.CYAN}Enter IP address or domain:{C.RESET} ").strip()
    if not target:
        warn("No input provided.")
        return

    # Resolve domain → IP
    ip = target
    if not target.replace(".", "").isdigit():
        try:
            ip = socket.gethostbyname(target)
            info(f"Resolved {C.WHITE}{target}{C.RESET} → {C.YELLOW}{ip}{C.RESET}")
        except socket.gaierror:
            warn(f"Cannot resolve: {target}")
            return
    else:
        info(f"Target IP: {C.YELLOW}{ip}{C.RESET}")

    # Reverse DNS (PTR)
    ptr = _reverse_dns(ip)
    divider("PTR RECORD")
    ok("Reverse DNS (PTR)", ptr)

    # Shared hosting lookup
    divider("SHARED HOSTING CHECK")
    info(f"Querying HackerTarget for domains on {C.YELLOW}{ip}{C.RESET}...")
    domains = _hackertarget_reverse(ip)

    if domains:
        print(f"\n  {C.GREEN}Found {len(domains)} domain(s) on this IP:{C.RESET}\n")
        for d in domains[:100]:  # cap display at 100
            ok(d, "")
        if len(domains) > 100:
            info(f"...and {len(domains) - 100} more (see report)")
    else:
        info("No shared domains found, or this IP is dedicated.")

    path = save_report("reverse_ip", ip, {"ip": ip, "ptr": ptr, "domains": domains})
    print(f"\n  {C.GRAY}Report saved → {path}{C.RESET}\n")
    return domains
