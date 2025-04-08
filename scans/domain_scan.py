import socket
import whois
import requests
import pycountry
import time
from termcolor import colored
from configparser import ConfigParser
import os

config = ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '..', 'API.config'))
VT_API_KEY = config.get("API_KEYS", "VT_API_KEY", fallback="")
URLSCAN_API_KEY = config.get("API_KEYS", "URLSCAN_API_KEY", fallback="")

def get_country_name(code):
    country = pycountry.countries.get(alpha_2=code)
    return country.name if country else 'Unknown'

def domain_scan(domain):
    print("🔍 Running Domain Scan...")
    print("")

    # WHOIS
    print(colored('###### Who Is Results ######', 'green'))
    try:
        whoarray = whois.whois(domain)
        for key, value in whoarray.items():
            print('[+] ' + f"{key}: {colored(value, 'blue')}")
        print("")    
    except:
        print(colored('[!] WHOIS lookup failed.', 'yellow'))
        print("")

    # Reverse DNS Lookup
    print(colored('###### Reverse DNS Lookup ######', 'green'))
    try:
        resolved = socket.gethostbyaddr(domain)
        print('[+] This domain resolves to: ' + colored(resolved[0], 'blue'))
        print("")
    except:
        print(colored('[+] Domain is not resolvable', 'yellow'))
        print("")

    # URLScan.io
    print(colored('###### URLScan.io Results ######', 'green'))
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    data = {"url": f"http://{domain}", "visibility": "public"}
    try:
        response = requests.post("https://urlscan.io/api/v1/scan/", json=data, headers=headers)
        if response.status_code == 200:
            scan_id = response.json().get("uuid")
            print(f"[+] Scan submitted! ID:", colored(scan_id, 'blue'))
            print("[!] Waiting for results...")
            time.sleep(15)
            result = requests.get(f"https://urlscan.io/api/v1/result/{scan_id}/")
            if result.status_code == 200:
                result_data = result.json()
                country_name = get_country_name(result_data.get("page", {}).get("country", ""))
                print("[+] Page Title:", colored(result_data.get("page", {}).get("title", "N/A"), "blue"))
                print("[+] IP:", colored(result_data.get("page", {}).get("ip", "N/A"), "blue"))
                print("[+] Country:", colored(country_name, "blue"))
                print("[+] URL:", colored(result_data.get("page", {}).get("url", "N/A"), "blue"))
                print("[+] Report URL:", colored(result_data.get("task", {}).get("reportURL", "N/A"), "blue"))
                print("[+] Verdict Score:", colored(result_data.get("verdicts", {}).get("overall", {}).get("score", "N/A"), "blue"))
                print("[+] Domain is Malicious:", colored(result_data.get("verdicts", {}).get("overall", {}).get("malicious", "N/A"), "blue"))
                print("")
            else:
                print(colored("[!] Could not retrieve URLScan.io results.", "yellow"))
                print("")
        else:
            print(colored("[!] URLScan.io scan request failed.", "yellow"))
            print("")
    except Exception as e:
        print(colored(f"[!] URLScan.io error: {e}", "yellow"))
        print("")

    # VirusTotal
    print(colored('###### Virus Total Results ######', 'green'))
    vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(vt_url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        gui_url = f"https://www.virustotal.com/gui/domain/{domain}"
        print('[+] Virus Total URL:', colored(gui_url, 'blue'))
        print('[+] Malicious:', colored(stats.get('malicious', 0), 'red'))
        print('[+] Suspicious:', colored(stats.get('suspicious', 0), 'yellow'))
        print('[+] Harmless:', colored(stats.get('harmless', 0), 'green'))
        print('[+] Undetected:', colored(stats.get('undetected', 0), 'blue'))
        print("")
    else:
        print(colored("[!] VirusTotal lookup failed", 'yellow'))
        print("")
