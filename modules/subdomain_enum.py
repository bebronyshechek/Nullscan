"""
subdomain_enum.py — Multithreaded subdomain enumerator with wildcard detection
"""

import socket
import concurrent.futures
import os

from modules.display import C, divider, ok, warn, info, progress, section
from modules.reporter import save_report

# ── Built-in wordlist (used if no external file found) ──
BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "ns3",
    "webdisk", "vpn", "m", "shop", "admin", "blog", "dev", "api", "test",
    "portal", "remote", "server", "mx", "imap", "cdn", "app", "staging",
    "beta", "cloud", "media", "support", "forum", "wiki", "git", "jenkins",
    "dashboard", "monitor", "status", "auth", "login", "secure", "cp",
    "cpanel", "whm", "autodiscover", "autoconfig", "mobile", "help", "docs",
    "static", "assets", "img", "images", "video", "upload", "uploads",
    "download", "downloads", "backup", "db", "database", "mysql", "sql",
    "ftp2", "sftp", "ssh", "proxy", "gateway", "intranet", "extranet",
    "exchange", "owa", "crm", "erp", "jira", "confluence", "gitlab",
    "github", "bitbucket", "ci", "build", "deploy", "prod", "production",
    "uat", "qa", "sandbox", "lab", "internal", "corp", "vpn2", "sso",
    "oauth", "id", "identity", "accounts", "account", "user", "users",
    "panel", "control", "manage", "management", "console", "web", "web2",
    "new", "old", "www2", "www3", "store", "pay", "payment", "billing",
    "invoice", "hr", "careers", "jobs", "legal", "privacy", "terms",
    "redirect", "link", "go", "click", "track", "analytics", "metrics",
    "grafana", "kibana", "elastic", "search", "solr", "redis", "mongo",
    "kafka", "rabbitmq", "smtp2", "relay", "outbound", "inbound",
]

WORDLIST_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "wordlists", "subdomains.txt"
)


def _load_wordlist() -> list:
    if os.path.isfile(WORDLIST_PATH):
        with open(WORDLIST_PATH) as f:
            words = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        info(f"Loaded {C.YELLOW}{len(words)}{C.RESET} words from {WORDLIST_PATH}")
        return words
    info(f"No external wordlist found, using built-in ({len(BUILTIN_WORDLIST)} words)")
    info(f"Tip: drop a subdomains.txt into {C.WHITE}wordlists/{C.RESET} for better results")
    return BUILTIN_WORDLIST


def _detect_wildcard(domain: str) -> str | None:
    """Return wildcard IP if domain uses wildcard DNS, else None."""
    test = f"__nullscan_wildcard_test__.{domain}"
    try:
        return socket.gethostbyname(test)
    except socket.gaierror:
        return None


def _check(sub: str, domain: str, wildcard_ip: str | None):
    hostname = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(hostname)
        if wildcard_ip and ip == wildcard_ip:
            return None   # wildcard match — skip
        return {"subdomain": hostname, "ip": ip}
    except socket.gaierror:
        return None


def subdomain_enum():
    section("SUBDOMAIN ENUMERATOR")
    domain = input(f"  {C.CYAN}Enter domain (e.g. example.com):{C.RESET} ").strip().lower()
    if not domain:
        warn("No input provided.")
        return

    wordlist = _load_wordlist()

    # Wildcard detection
    print(f"\n  {C.GRAY}Checking for wildcard DNS...{C.RESET}")
    wildcard_ip = _detect_wildcard(domain)
    if wildcard_ip:
        info(f"{C.YELLOW}Wildcard DNS detected{C.RESET} — all non-existent subdomains resolve to {C.YELLOW}{wildcard_ip}{C.RESET}")
        info("Wildcard results will be filtered out automatically.")
    else:
        info("No wildcard DNS detected — good.")

    print(f"\n  {C.GRAY}Scanning {len(wordlist)} subdomains...{C.RESET}\n")
    found = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(_check, sub, domain, wildcard_ip): sub
            for sub in wordlist
        }
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            progress(i, len(wordlist))
            result = future.result()
            if result:
                found.append(result)

    print()
    divider("RESULTS")

    if found:
        print(f"  {C.GREEN}Found {len(found)} subdomain(s):{C.RESET}\n")
        for entry in sorted(found, key=lambda x: x["subdomain"]):
            ok(entry["subdomain"], entry["ip"])
    else:
        warn("No subdomains found. Try a larger wordlist.")

    path = save_report("subdomain_enum", domain, {"found": found, "total_checked": len(wordlist)})
    print(f"\n  {C.GRAY}Report saved → {path}{C.RESET}\n")
    return found
