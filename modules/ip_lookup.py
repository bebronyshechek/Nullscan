"""
ip_lookup.py — IP Geolocation + Threat Intel via ip-api.com & AbuseIPDB
"""

import json
import urllib.request
import urllib.error
import socket

from modules.display import C, divider, ok, warn, info, flag, section
from modules.reporter import save_report


def _query_ipapi(ip: str) -> dict | None:
    fields = (
        "status,message,continent,continentCode,country,countryCode,"
        "regionName,city,district,zip,lat,lon,timezone,offset,currency,"
        "isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    )
    url = f"http://ip-api.com/json/{ip}?fields={fields}"
    try:
        req = urllib.request.urlopen(url, timeout=8)
        return json.loads(req.read().decode())
    except Exception as e:
        warn(f"ip-api.com error: {e}")
        return None


def _try_reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def ip_lookup():
    section("IP LOOKUP & GEOLOCATION")
    target = input(f"  {C.CYAN}Enter IP address (or domain):{C.RESET} ").strip()
    if not target:
        warn("No input provided.")
        return

    # Resolve domain → IP if needed
    resolved_ip = target
    if not target.replace(".", "").isdigit():
        try:
            resolved_ip = socket.gethostbyname(target)
            info(f"Resolved {C.WHITE}{target}{C.RESET} → {C.YELLOW}{resolved_ip}{C.RESET}")
        except socket.gaierror:
            warn(f"Cannot resolve: {target}")
            return

    print(f"\n  {C.GRAY}Querying ip-api.com...{C.RESET}\n")
    data = _query_ipapi(resolved_ip)
    if not data:
        return
    if data.get("status") == "fail":
        warn(f"Lookup failed: {data.get('message', 'unknown')}")
        return

    # ── Geolocation ──
    divider("GEOLOCATION")
    ok("IP Address",   data.get("query",        "N/A"))
    ok("Hostname",     data.get("reverse") or _try_reverse_dns(resolved_ip))
    ok("Continent",    f"{data.get('continent','N/A')} ({data.get('continentCode','?')})")
    ok("Country",      f"{data.get('country','N/A')} ({data.get('countryCode','?')})")
    ok("Region",       data.get("regionName",   "N/A"))
    ok("City",         data.get("city",         "N/A"))
    ok("District",     data.get("district",     "N/A") or "N/A")
    ok("ZIP Code",     data.get("zip",          "N/A"))
    ok("Coordinates",  f"{data.get('lat','?')}, {data.get('lon','?')}")
    ok("Timezone",     data.get("timezone",     "N/A"))
    ok("UTC Offset",   str(data.get("offset", 0)) + "s")
    ok("Currency",     data.get("currency",     "N/A"))

    # ── Network ──
    divider("NETWORK INFO")
    ok("ISP",          data.get("isp",    "N/A"))
    ok("Organization", data.get("org",    "N/A"))
    ok("ASN",          data.get("as",     "N/A"))
    ok("ASN Name",     data.get("asname", "N/A"))

    # ── Risk Flags ──
    divider("RISK FLAGS")
    is_proxy   = data.get("proxy",   False)
    is_mobile  = data.get("mobile",  False)
    is_hosting = data.get("hosting", False)

    _rflag("Proxy / VPN / Tor", is_proxy)
    _rflag("Mobile Network",    is_mobile)
    _rflag("Datacenter / Host", is_hosting)

    # ── Save report ──
    report_data = {**data, "reverse_dns": _try_reverse_dns(resolved_ip)}
    path = save_report("ip_lookup", resolved_ip, report_data)
    print(f"\n  {C.GRAY}Report saved → {path}{C.RESET}\n")
    return report_data


def _rflag(label, value):
    if value:
        flag(label, "YES ⚑")
    else:
        ok(label, "No")
