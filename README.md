# OSINT.py
The general consensus is that open source intelligence shouldn't be hard 

**OSINT.py** is a terminal-based tool for investigating IOCs (indicators of compromise) — including IPs, domains, URLs, and file hashes. It’s powered by trusted APIs like VirusTotal, URLScan.io, AbuseIPDB, Hybrid Analysis, and WHOIS, making it easy to get actionable insights fast.

It outputs the results in your terminal, and if you add `--output`, it’ll automatically generate a clean, timestamped log file.

Built for threat hunters, SOC analysts, and digital sleuths who want quick answers without the bloat 🕵️‍♂️⚡

## Structure:

```graphql
OSINT-Scanner/
├── OSINT.py                  # Main CLI script with argparse, banner, and scan routing
├── API.config                # Stores your API keys securely
├── requirements.txt          # Lists all Python dependencies
├── scan_YYYY-MM-DD_HHMM.txt  # Auto-generated scan logs (if --output is used)
├── scans/                    # Modular scan logic lives here
│   ├── ip_scan.py
│   ├── domain_scan.py
│   ├── url_scan.py
│   ├── hash_scan.py
│   ├── email_scan.py         # Placeholder
│   ├── account_scan.py       # Placeholder
└── install.bat     # Optional: batch file to install deps and prep environment
```


### Onboarded Tools:
- Virus Total
- URLScan.io
- Hybrid Analysis
- AbuseIPDB
- Hunter.io

### Soon To come:
- Malware Bazar
- CloudFlare Radar
- HaveIBeenPwned
- ChatGPT (eventually)

Pre-requesites:
As This will requires the appropriate tooling API, personal API keys are required,
These will be insertable into the API.config file, and any missing API's will just be skipped
Python 3 is also required


## Getting Started

#### 1. **Clone or Download the Repo**

```bash
git clone https://github.com/your-username/OSINT.py.git
cd OSINT.py
```

#### 2. **Install Dependencies**

Use the provided batch file (Windows): install_and_setup.bat

Or manually:

```bash
pip install -r requirements.txt
```

#### 3. **Set Up Your API Keys**

Create a file named `API.config` in the root folder with the following format:
A template has been added for ease of use, the values in here can just be changed

```ini
[API_KEYS]
VT_API_KEY = your_virustotal_key
URLSCAN_API_KEY = your_urlscan_key
ABUSEIPDB_API_KEY = your_abuseipdb_key
HYBRID_API_KEY = your_hybrid_analysis_key
```

Only fill in the keys you need — unused services can be left out.

#### 4. **Run the Tool**

Basic usage:

```bash
python OSINT.py --ip 8.8.8.8
python OSINT.py --url https://example.com
python OSINT.py --domain example.com
python OSINT.py --hash xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
python OSINT.py --email jogn.doe@example.com 
python OSINT.py --account john.doe
```

#### 5. **Optional: Save Results to File**

Use the `--output` flag:

```bash
python OSINT.py --domain example.com --output
```

This creates `scan_YYYY-MM-DD_HHMM.txt` automatically. Or specify a custom filename:

```bash
python OSINT.py --hash abc123... --output results.txt
```

---

Happy scanning! 🕵️‍♂️

The intended outcome of this tool is the following 
