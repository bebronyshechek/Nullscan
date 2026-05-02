"""
header_analyzer.py — HTTP response header security analyzer
"""

import urllib.request
import urllib.error
import ssl

from modules.display import C, divider, ok, warn, flag, info, section
from modules.reporter import save_report

# ── Security headers to check ──
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc":    "HSTS — forces HTTPS",
        "good":    True,
        "risk":    "Site can be accessed over HTTP (downgrade attack)",
    },
    "Content-Security-Policy": {
        "desc":    "CSP — prevents XSS",
        "good":    True,
        "risk":    "XSS attacks may succeed",
    },
    "X-Frame-Options": {
        "desc":    "Clickjacking protection",
        "good":    True,
        "risk":    "Site may be embeddable in iframes (clickjacking)",
    },
    "X-Content-Type-Options": {
        "desc":    "MIME-type sniffing protection",
        "good":    True,
        "risk":    "Browser may sniff MIME types",
    },
    "Referrer-Policy": {
        "desc":    "Controls referrer info leakage",
        "good":    True,
        "risk":    "Referrer data may be leaked",
    },
    "Permissions-Policy": {
        "desc":    "Controls browser features",
        "good":    True,
        "risk":    "Browser features not restricted",
    },
    "X-XSS-Protection": {
        "desc":    "Legacy XSS filter (older browsers)",
        "good":    True,
        "risk":    "Older browsers lack XSS protection",
    },
    "Server": {
        "desc":    "Server software disclosure",
        "good":    False,   # presence is bad
        "risk":    "Server version disclosed — info leak",
    },
    "X-Powered-By": {
        "desc":    "Backend tech disclosure",
        "good":    False,
        "risk":    "Backend technology disclosed — info leak",
    },
    "X-AspNet-Version": {
        "desc":    "ASP.NET version disclosure",
        "good":    False,
        "risk":    "ASP.NET version exposed",
    },
}

# Headers that hint at interesting tech
INTERESTING_HEADERS = [
    "Via", "X-Cache", "X-Cache-Status", "CF-Ray", "X-Served-By",
    "X-Varnish", "Age", "X-Request-Id", "X-Correlation-Id",
    "Access-Control-Allow-Origin", "Set-Cookie",
]


def _fetch_headers(url: str) -> dict | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (NullScan Recon Framework)"}
        )
        resp = urllib.request.urlopen(req, timeout=10, context=ctx)
        return dict(resp.headers), resp.geturl(), resp.status
    except urllib.error.HTTPError as e:
        # Still return headers even on 4xx/5xx
        return dict(e.headers), url, e.code
    except urllib.error.URLError as e:
        warn(f"Connection error: {e.reason}")
        return None
    except Exception as e:
        warn(f"Error: {e}")
        return None


def header_analyzer():
    section("HTTP HEADER ANALYZER")
    host = input(f"  {C.CYAN}Enter domain or URL:{C.RESET} ").strip()
    if not host:
        warn("No input provided.")
        return

    # Normalize to URL
    if not host.startswith("http"):
        urls_to_try = [f"https://{host}", f"http://{host}"]
    else:
        urls_to_try = [host]

    headers = None
    final_url = None
    status = None

    for url in urls_to_try:
        info(f"Fetching {C.WHITE}{url}{C.RESET}...")
        result = _fetch_headers(url)
        if result:
            headers, final_url, status = result
            break

    if not headers:
        warn("Could not fetch headers.")
        return

    # ── Response Info ──
    divider("RESPONSE INFO")
    ok("Final URL",    final_url)
    ok("Status Code",  str(status))
    ok("Server",       headers.get("Server", "Not disclosed"))
    ok("Content-Type", headers.get("Content-Type", "N/A"))

    # ── Security headers ──
    divider("SECURITY HEADERS")
    score = 0
    max_score = sum(1 for h in SECURITY_HEADERS.values() if h["good"])

    for header, meta in SECURITY_HEADERS.items():
        value = headers.get(header)
        present = value is not None
        should_be_present = meta["good"]

        if should_be_present:
            if present:
                ok(header, value[:70])
                score += 1
            else:
                flag(header, f"MISSING — {meta['risk']}")
        else:  # bad if present
            if present:
                flag(header, f"{value} — {meta['risk']}")
            else:
                ok(header, "Not present (good)")

    # ── Security score ──
    divider("SECURITY SCORE")
    pct = int((score / max_score) * 100)
    bar_len = 30
    filled  = int(bar_len * score / max_score)
    bar_color = C.GREEN if pct >= 70 else (C.YELLOW if pct >= 40 else C.RED)
    bar = f"{bar_color}{'█'*filled}{C.GRAY}{'░'*(bar_len-filled)}{C.RESET}"
    grade = "A" if pct >= 80 else ("B" if pct >= 60 else ("C" if pct >= 40 else ("D" if pct >= 20 else "F")))
    print(f"\n  {bar}  {bar_color}{pct}%  Grade: {grade}{C.RESET}\n")

    # ── Interesting headers ──
    divider("INFRASTRUCTURE HINTS")
    found_any = False
    for h in INTERESTING_HEADERS:
        val = headers.get(h)
        if val:
            ok(h, val[:80])
            found_any = True
    if not found_any:
        info("No notable infrastructure headers found.")

    # ── All headers (raw) ──
    show_all = input(f"\n  {C.CYAN}Show all raw headers? [y/N]:{C.RESET} ").strip().lower()
    if show_all == "y":
        divider("ALL HEADERS")
        for k, v in sorted(headers.items()):
            ok(k, v[:80])

    path = save_report("header_analyzer", host, {
        "url": final_url,
        "status": status,
        "security_score": pct,
        "grade": grade,
        "headers": dict(headers)
    })
    print(f"\n  {C.GRAY}Report saved → {path}{C.RESET}\n")
    return headers
