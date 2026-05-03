# 👻 NullScan

> A terminal-based penetration testing recon framework built in pure Python.

```
███╗   ██╗██╗   ██╗██╗     ██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║██║   ██║██║     ██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║██║   ██║██║     ██║     ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║██║   ██║██║     ██║     ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║╚██████╔╝███████╗███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

**For authorized penetration testing and educational use only.**

---

## Tools

| # | Tool | Description |
|---|------|-------------|
| 1 | IP Lookup | Geolocation, ISP, ASN, proxy/VPN detection |
| 2 | Subdomain Enumerator | Multithreaded DNS brute-force with wildcard detection |
| 3 | Port Scanner | TCP scan with banner grabbing & dangerous port flags |
| 4 | WHOIS + DNS Recon | Full DNS records + SPF/DMARC/CAA checks + zone transfer test |
| 5 | HTTP Header Analyzer | Security header audit with letter grade scoring |
| 6 | Reverse IP Lookup | Find other domains hosted on the same IP |
| 7 | Full Auto Recon | Chains tools 1, 3, 4, and 5 automatically |

---

## Install & Run

```bash
# Clone
git clone git clone https://github.com/bebronyshechek/nullscan.git
cd nullscan

# Install system deps (Debian/Ubuntu/Kali)
sudo apt install dnsutils whois

# Run
python3 nullscan.py
```

### Direct (non-interactive) mode

```bash
python3 nullscan.py --tool 1 --target 8.8.8.8
python3 nullscan.py --tool 4 --target example.com
```

---

## Requirements

- Python 3.10+
- `dig` (dnsutils)
- `whois`
- No pip packages needed — pure stdlib

---

## Bigger Wordlist (optional)

For better subdomain enumeration, drop a wordlist into `wordlists/subdomains.txt`:

```bash
# From SecLists:
curl -o wordlists/subdomains.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
```

---

## Output

All scan results are automatically saved as JSON to `output/`:

```
output/
  ip_lookup_8_8_8_8_20241201_143022.json
  port_scan_example_com_20241201_143145.json
  dns_recon_example_com_20241201_143210.json
```

---

## Disclaimer

This tool is intended **only** for authorized security testing and educational purposes.
Do not use against systems you do not own or have explicit permission to test.
The author is not responsible for any misuse or damage.

---

## License

MIT
