"""
port_scanner.py — Threaded port scanner with banner grabbing & service detection
"""

import socket
import concurrent.futures
import time

from modules.display import C, divider, ok, warn, info, flag, progress, section
from modules.reporter import save_report

# ── Service map (port → name) ──
SERVICE_MAP = {
    20: "FTP-Data",     21: "FTP",          22: "SSH",
    23: "Telnet",       25: "SMTP",         53: "DNS",
    67: "DHCP",         68: "DHCP-Client",  69: "TFTP",
    80: "HTTP",         88: "Kerberos",     110: "POP3",
    111: "RPCbind",     119: "NNTP",        123: "NTP",
    135: "MS-RPC",      137: "NetBIOS-NS",  138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP",        161: "SNMP",
    389: "LDAP",        443: "HTTPS",       445: "SMB",
    465: "SMTPS",       500: "IKE/IPSec",   514: "Syslog",
    587: "SMTP-Sub",    631: "IPP",         636: "LDAPS",
    873: "rsync",       993: "IMAPS",       995: "POP3S",
    1080: "SOCKS",      1194: "OpenVPN",    1433: "MSSQL",
    1521: "Oracle-DB",  1723: "PPTP",       2049: "NFS",
    2082: "cPanel",     2083: "cPanel-SSL", 2181: "ZooKeeper",
    2375: "Docker",     2376: "Docker-TLS", 3000: "Dev-Server",
    3306: "MySQL",      3389: "RDP",        4369: "Erlang/RabbitMQ",
    4444: "Metasploit", 5000: "Flask/Dev",  5432: "PostgreSQL",
    5601: "Kibana",     5672: "RabbitMQ",   5900: "VNC",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",6379: "Redis",
    6443: "K8s-API",    7070: "RealServer", 7777: "Oracle-HTTP",
    8000: "HTTP-Alt",   8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "Jupyter",    9000: "PHP-FPM",    9090: "Prometheus",
    9100: "Printer",    9200: "Elasticsearch", 9300: "ES-Transport",
    10000: "Webmin",    11211: "Memcached", 15672: "RabbitMQ-Mgmt",
    27017: "MongoDB",   27018: "MongoDB",   50000: "SAP",
    50070: "Hadoop",
}

# Ports that are worth flagging as dangerous when open
DANGEROUS_PORTS = {23, 135, 137, 139, 445, 1433, 3389, 4444, 5900, 6379, 11211, 27017}


def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Try to grab a service banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            # Send HTTP request for web ports
            if port in (80, 8080, 8000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            try:
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                return banner.splitlines()[0][:80] if banner else ""
            except Exception:
                return ""
    except Exception:
        return ""


def _scan_port(host: str, port: int, timeout: float = 0.8) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                return {"port": port}
    except Exception:
        pass
    return None


def port_scanner():
    section("PORT SCANNER")
    host = input(f"  {C.CYAN}Enter host or IP:{C.RESET} ").strip()
    if not host:
        warn("No input provided.")
        return

    # Resolve
    try:
        ip = socket.gethostbyname(host)
        if ip != host:
            info(f"Resolved {C.WHITE}{host}{C.RESET} → {C.YELLOW}{ip}{C.RESET}")
        else:
            info(f"Target: {C.YELLOW}{ip}{C.RESET}")
    except socket.gaierror:
        warn(f"Cannot resolve host: {host}")
        return

    print(f"""
  {C.CYAN}[1]{C.WHITE}  Common ports  ({len(SERVICE_MAP)} ports)
  {C.CYAN}[2]{C.WHITE}  Standard scan (1–1024)
  {C.CYAN}[3]{C.WHITE}  Full scan     (1–65535)  {C.GRAY}— slow{C.RESET}
  {C.CYAN}[4]{C.WHITE}  Custom range{C.RESET}
""")
    choice = input(f"  {C.CYAN}Choice:{C.RESET} ").strip()

    if choice == "1":
        ports = list(SERVICE_MAP.keys())
        timeout = 0.8
    elif choice == "2":
        ports = list(range(1, 1025))
        timeout = 0.6
    elif choice == "3":
        ports = list(range(1, 65536))
        timeout = 0.4
        warn("Full scan — this may take several minutes.")
    elif choice == "4":
        rng = input(f"  {C.CYAN}Enter range (e.g. 1-500):{C.RESET} ").strip()
        try:
            start_p, end_p = map(int, rng.split("-"))
            ports = list(range(start_p, end_p + 1))
            timeout = 0.7
        except Exception:
            warn("Invalid range format. Use: start-end")
            return
    else:
        warn("Invalid choice.")
        return

    grab_banners = input(f"\n  {C.CYAN}Grab service banners? [y/N]:{C.RESET} ").strip().lower() == "y"

    print(f"\n  {C.GRAY}Scanning {len(ports)} ports on {ip}...{C.RESET}\n")
    open_ports = []
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        futures = {executor.submit(_scan_port, ip, p, timeout): p for p in ports}
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            progress(i, len(ports))
            result = future.result()
            if result:
                open_ports.append(result)

    print()

    # Banner grabbing (sequential to avoid hammering)
    if grab_banners and open_ports:
        print(f"\n  {C.GRAY}Grabbing banners...{C.RESET}")
        for entry in open_ports:
            banner = _grab_banner(ip, entry["port"])
            entry["banner"] = banner

    elapsed = time.time() - start_time
    divider("RESULTS")

    if open_ports:
        print(f"  {C.GREEN}Found {len(open_ports)} open port(s) in {elapsed:.1f}s:{C.RESET}\n")
        for entry in sorted(open_ports, key=lambda x: x["port"]):
            port    = entry["port"]
            service = SERVICE_MAP.get(port, "Unknown")
            banner  = entry.get("banner", "")
            label   = f"Port {port}/{service}"
            value   = banner if banner else "open"

            if port in DANGEROUS_PORTS:
                flag(label, value + "  ⚑ potentially dangerous")
            else:
                ok(label, value)
    else:
        warn(f"No open ports found. ({elapsed:.1f}s)")

    path = save_report("port_scan", host, {
        "ip": ip,
        "open_ports": open_ports,
        "scanned": len(ports),
        "elapsed": round(elapsed, 2)
    })
    print(f"\n  {C.GRAY}Report saved → {path}{C.RESET}\n")
    return open_ports
