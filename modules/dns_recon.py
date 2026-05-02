"""
dns_recon.py — WHOIS + full DNS record enumeration
"""

import subprocess
import socket

from modules.display import C, divider, ok, warn, info, section
from modules.reporter import save_report

DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA", "DMARC"]

WHOIS_KEYS = [
    "domain name", "registrar", "registrar url", "creation date",
    "updated date", "registry expiry date", "expiry date",
    "name server", "registrant name", "registrant organization",
    "registrant email", "registrant country", "admin email",
    "tech email", "dnssec", "status",
]


def _dig(domain: str, rtype: str) -> list[str]:
    try:
        # PTR needs reversed IP format
        if rtype == "PTR" and not domain.endswith(".arpa"):
            parts = domain.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                domain = ".".join(reversed(parts)) + ".in-addr.arpa"
            else:
                return []

        # DMARC is a TXT record under _dmarc subdomain
        query_domain = f"_dmarc.{domain}" if rtype == "DMARC" else domain
        rtype_arg = "TXT" if rtype == "DMARC" else rtype

        result = subprocess.run(
            ["dig", "+short", "+time=3", "+tries=2", rtype_arg, query_domain],
            capture_output=True, text=True, timeout=8
        )
        return [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
    except FileNotFoundError:
        return ["[dig not installed — run: sudo apt install dnsutils]"]
    except subprocess.TimeoutExpired:
        return ["[timeout]"]
    except Exception as e:
        return [f"Error: {e}"]


def _whois(domain: str) -> dict:
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=12
        )
        lines = result.stdout.splitlines()
        parsed = {}
        for line in lines:
            if ":" not in line:
                continue
            lower = line.lower()
            for key in WHOIS_KEYS:
                if lower.strip().startswith(key):
                    label = key.strip().title()
                    value = line.partition(":")[2].strip()
                    if value and label not in parsed:
                        parsed[label] = value
        return parsed
    except FileNotFoundError:
        return {"Error": "whois not installed — run: sudo apt install whois"}
    except subprocess.TimeoutExpired:
        return {"Error": "whois timed out"}
    except Exception as e:
        return {"Error": str(e)}


def _zone_transfer(domain: str, ns_list: list[str]) -> list[str]:
    """Attempt AXFR zone transfer against each nameserver — usually fails (as it should)."""
    results = []
    for ns in ns_list:
        ns_clean = ns.rstrip(".")
        try:
            result = subprocess.run(
                ["dig", "AXFR", domain, f"@{ns_clean}"],
                capture_output=True, text=True, timeout=8
            )
            if "Transfer failed" in result.stdout or not result.stdout.strip():
                results.append(f"{ns_clean} → Transfer refused (secure)")
            else:
                results.append(f"{ns_clean} → {C.RED}ZONE TRANSFER POSSIBLE!{C.RESET}")
        except Exception:
            results.append(f"{ns_clean} → error")
    return results


def dns_recon():
    section("WHOIS + DNS RECON")
    domain = input(f"  {C.CYAN}Enter domain (e.g. example.com):{C.RESET} ").strip().lower()
    if not domain:
        warn("No input provided.")
        return

    report_data = {"domain": domain, "whois": {}, "dns": {}, "zone_transfer": []}

    # ── WHOIS ──
    divider("WHOIS DATA")
    print(f"  {C.GRAY}Running whois...{C.RESET}\n")
    whois_data = _whois(domain)
    report_data["whois"] = whois_data
    if whois_data:
        for k, v in whois_data.items():
            ok(k, v)
    else:
        warn("No WHOIS data returned.")

    # ── DNS Records ──
    divider("DNS RECORDS")
    print(f"  {C.GRAY}Querying {len(DNS_TYPES)} record types...{C.RESET}\n")

    ns_servers = []
    for rtype in DNS_TYPES:
        records = _dig(domain, rtype)
        report_data["dns"][rtype] = records

        if records:
            print(f"  {C.CYAN}{rtype:<8}{C.RESET}{C.YELLOW}{records[0]}{C.RESET}")
            for r in records[1:]:
                print(f"  {'':8}{C.YELLOW}{r}{C.RESET}")
            if rtype == "NS":
                ns_servers = records
        else:
            print(f"  {C.CYAN}{rtype:<8}{C.RESET}{C.GRAY}(none){C.RESET}")

    # ── Security record checks ──
    divider("SECURITY CHECKS")
    spf_records  = [r for r in report_data["dns"].get("TXT", []) if "v=spf1" in r.lower()]
    dkim_records = []  # would need selector guessing — skip for now
    dmarc        = report_data["dns"].get("DMARC", [])
    caa          = report_data["dns"].get("CAA", [])

    _sec_check("SPF Record",   bool(spf_records),  spf_records[0][:60] if spf_records else "MISSING — spoofing risk")
    _sec_check("DMARC Record", bool(dmarc),         dmarc[0][:60] if dmarc else "MISSING — email spoofing risk")
    _sec_check("CAA Record",   bool(caa),           caa[0][:60] if caa else "MISSING — any CA can issue certs")

    # ── Zone Transfer attempt ──
    if ns_servers:
        divider("ZONE TRANSFER TEST")
        print(f"  {C.GRAY}Testing AXFR against {len(ns_servers)} nameserver(s)...{C.RESET}\n")
        zt_results = _zone_transfer(domain, ns_servers)
        report_data["zone_transfer"] = zt_results
        for r in zt_results:
            info(r)

    path = save_report("dns_recon", domain, report_data)
    print(f"\n  {C.GRAY}Report saved → {path}{C.RESET}\n")
    return report_data


def _sec_check(label: str, present: bool, detail: str):
    from modules.display import flag
    if present:
        ok(label, detail)
    else:
        flag(label, detail)
