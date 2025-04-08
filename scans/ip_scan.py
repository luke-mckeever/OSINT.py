import socket
import whois
import requests
import pycountry
from termcolor import colored
from configparser import ConfigParser
import os

config = ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '..', 'API.config'))
VT_API_KEY = config.get("API_KEYS", "VT_API_KEY", fallback="")
ABUSEIPDB_API_KEY = config.get("API_KEYS", "ABUSEIPDB_API_KEY", fallback="")

def get_country_name(code):
    country = pycountry.countries.get(alpha_2=code)
    return country.name if country else 'Unknown'

def ip_scan(ip):
    print("🔍 Running IP Scan...")
    print("")

    # WHOIS
    print(colored('###### Who Is Results ######', 'green'))
    try:
        whoarray = whois.whois(ip)
        for key, value in whoarray.items():
            print('[+] ' + f"{key}: {colored(value, 'blue')}")
            print("")
    except:
        print(colored('[!] WHOIS failed.', 'yellow'))
        print("")

    # Reverse IP Lookup
    print(colored('###### Reverse IP Lookup ######', 'green'))
    try:
        rev = socket.gethostbyaddr(ip)
        print('[+] This IP resolves to: ' + colored(rev[0], 'blue'))
        print("")
    except:
        print(colored('[+] IP is not resolvable', 'yellow'))
        print("")

    # AbuseIPDB
    print(colored('###### Abuse IPDB Results #######', 'green'))
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    response = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
    if response.status_code == 200:
        d = response.json()['data']
        print(f"[+] IP Address: {colored(d['ipAddress'], 'blue')}")
        print(f"[+] Is Whitelisted: {colored('Yes' if d['isWhitelisted'] else 'No', 'blue')}")
        print(f"[+] Country: {colored(get_country_name(d['countryCode']), 'blue')}")
        print(f"[+] Domain: {colored(d['domain'], 'blue')}")
        print(f"[+] Reports: {colored(d['totalReports'], 'blue')}")
        print(f"[+] Last Report: {colored(d['lastReportedAt'], 'blue')}")
        print("")
    else:
        print(colored("[!] AbuseIPDB lookup failed", 'yellow'))
        print("")

    # VirusTotal
    print(colored('###### Virus Total Results ######', 'green'))
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    response = requests.get(vt_url, headers={"x-apikey": VT_API_KEY})
    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        print('[+] Virus Total URL:', colored(vt_url, 'red'))
        print('[+] Malicious:', colored(stats.get('malicious', 0), 'red'))
        print('[+] Suspicious:', colored(stats.get('suspicious', 0), 'yellow'))
        print('[+] Harmless:', colored(stats.get('harmless', 0), 'green'))
        print('[+] Undetected:', colored(stats.get('undetected', 0), 'blue'))
        print("")
    else:
        print(colored("[!] VirusTotal lookup failed", 'yellow'))
        print("")
