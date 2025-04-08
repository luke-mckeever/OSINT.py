# OSINT.py
The general consensus is that open source intelligence shouldn't be hard 

**OSINT.py** is a terminal-based tool for investigating IOCs (indicators of compromise) — including IPs, domains, URLs, and file hashes. It’s powered by trusted APIs like VirusTotal, URLScan.io, AbuseIPDB, Hybrid Analysis, and WHOIS, making it easy to get actionable insights fast.

It outputs the results in your terminal, and if you add `--output`, it’ll automatically generate a clean, timestamped log file.

Built for threat hunters, SOC analysts, and digital sleuths who want quick answers without the bloat 🕵️‍♂️⚡

## Structure:

```graphql
OSINT.py
├── OSINT.py                  # Main CLI script with argparse, banner, and scan routing
├── API.config                # Stores your API keys securely
├── requirements.txt          # Lists all Python dependencies
├── scan_YYYY-MM-DD_HHMM.txt  # Auto-generated scan logs (if --output is used)
├── scans/                    # Modular scan logic lives here
│   ├── ip_scan.py
│   ├── domain_scan.py
│   ├── url_scan.py
│   ├── hash_scan.py
│   ├── email_scan.py         
│   ├── account_scan.py       # Placeholder
└── install.bat     # Optional: batch file to install deps and prep environment
```


### Onboarded Tools:
- Virus Total
- URLScan.io
- Hybrid Analysis (API undergoing maintenance)
- AbuseIPDB
- Hunter.io
- HaveIBeenPwned
- Malware Bazar

### Soon To come:
- CloudFlare Radar
- ChatGPT (eventually)

## How to Get your API Keys

> Please note all API's are not required for this tool to work. 

- ##### Virus Total - Create Your Account [Here](https://www.virustotal.com/gui/join-us) (FREE)
When logged in, use the drop down on the right and select `API Key` to obtain your key
- ##### URLScan.io - Create Your Account [Here](https://urlscan.io/user/signup) (FREE)
When logged in, browse to the [USER](https://urlscan.io/user/) page and click `settings & API` , to obtain your key click `+ New API key`
- ##### Abuse IPDB - Create Your Account [HERE](https://www.abuseipdb.com/register?plan=free) (FREE)
When logged in, browse to the [account api](https://www.abuseipdb.com/account/api) page and click `Create Key`
- ##### Hunter.io - Create Your Account [HERE](https://hunter.io/users/sign_up) (FREE)
When logged in, browse to the [API](https://hunter.io/api-keys) page, to obtain your key click `+ New key`
- ##### Hybrid Analysis - Create Your Account [HERE](https://www.hybrid-analysis.com/signup) (FREE)
When logged in, browse to [my account](https://www.hybrid-analysis.com/my-account), go to the [API key](https://www.hybrid-analysis.com/my-account?tab=%23api-key-tab) tab and create a new key
- ##### Have I Been Pwned - Obtain your key [Here](https://haveibeenpwned.com/API/Key])
You will receive an invite email to purchase the API, proceed though the instructions to obtain you key



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
python OSINT.py -ip 8.8.8.8
python OSINT.py -url https://example.com
python OSINT.py -domain example.com
python OSINT.py -hash xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
python OSINT.py -email jogn.doe@example.com 
python OSINT.py -account john.doe
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

