import socket
import whois
import requests
import pycountry
import time
import base64
from urllib.parse import urlparse
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

def url_scan(url):
    print("\U0001F50D Running URL Scan...")
    print("")

    # WHOIS
    print(colored('###### Who Is Results ######', 'green'))
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    try:
        whoarray = whois.whois(domain)
        for key, value in whoarray.items():
            print('[+] ' + f"{key}: {colored(value, 'red')}")
        print("")
    except:
        print(colored("[!] WHOIS lookup failed", "yellow"))
        print("")

    # Reverse DNS Lookup
    print(colored('###### Reverse DNS Lookup ######', 'green'))
    try:
        resolved = socket.gethostbyaddr(domain)
        print('[+] This domain resolves to: ' + colored(resolved[0], 'red'))
        print("")
    except:
        print(colored('[+] Domain is not resolvable', 'yellow'))
        print("")

    # URLScan.io
    print(colored('###### URLScan.io Results ######', 'green'))
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "public"}
    try:
        response = requests.post("https://urlscan.io/api/v1/scan/", json=data, headers=headers)
        if response.status_code == 200:
            scan_id = response.json().get("uuid")
            print(f"[+] Scan submitted! ID: {scan_id}")
            print("[!] Waiting for results...")
            
            for attempt in range(10):
                time.sleep(6)
                result = requests.get(f"https://urlscan.io/api/v1/result/{scan_id}/")
                if result.status_code == 200:
                    result_data = result.json()
                    break
                else:
                    print(f"[!] Attempt {attempt + 1}: Result not ready yet...")
            else:
                print(colored("[!] Could not retrieve URLScan.io results after multiple attempts", "yellow"))
                result_data = None

            if result_data:
                country_name = get_country_name(result_data.get("page", {}).get("country", ""))
                print("[+] Page Title:", colored(result_data.get("page", {}).get("title", "N/A"), "red"))
                print("[+] Domain:", colored(result_data.get("page", {}).get("domain", "N/A"), "red"))
                print("[+] IP:", colored(result_data.get("page", {}).get("ip", "N/A"), "red"))
                print("[+] Country:", colored(country_name, "red"))
                print("[+] URL:", colored(result_data.get("page", {}).get("url", "N/A"), "red"))
                print("[+] Report URL:", colored(result_data.get("task", {}).get("reportURL", "N/A"), "red"))
                print("[+] Screenshot URL:", colored(result_data.get("task", {}).get("screenshotURL", "N/A"), "red"))
                print("[+] Verdict Score:", colored(result_data.get("verdicts", {}).get("overall", {}).get("score", "N/A"), "red"))
                print("[+] Domain is Malicious:", colored(result_data.get("verdicts", {}).get("overall", {}).get("malicious", "N/A"), "red"))
                print("")
        else:
            print(colored("[!] URLScan.io scan request failed", "yellow"))
    except Exception as e:
        print(colored(f"[!] URLScan.io error: {e}", "yellow"))

    # VirusTotal
    print(colored('###### Virus Total Results ######', 'green'))
    try:
        submit_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": VT_API_KEY}
        submit_response = requests.post(submit_url, data={"url": url}, headers=headers)

        if submit_response.status_code == 200:
            analysis_id = submit_response.json()["data"]["id"]
            vt_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

            for attempt in range(10):
                time.sleep(6)
                response = requests.get(vt_url, headers=headers)
                data = response.json()
                status = data.get("data", {}).get("attributes", {}).get("status", "")
                if status == "completed":
                    stats = data.get("data", {}).get("attributes", {}).get("stats", {})
                    print('[+] Virus Total Analysis ID:', colored(analysis_id, 'red'))
                    print('[+] VirusTotal Report URL:', colored(f'https://www.virustotal.com/gui/url/{analysis_id}', 'red'))
                    print('[+] Malicious:', colored(stats.get('malicious', 0), 'red'))
                    print('[+] Suspicious:', colored(stats.get('suspicious', 0), 'yellow'))
                    print('[+] Harmless:', colored(stats.get('harmless', 0), 'green'))
                    print('[+] Undetected:', stats.get('undetected', 0))
                    break
                else:
                    print(f"[!] Attempt {attempt + 1}: VirusTotal scan still processing...")
            else:
                print(colored("[!] VirusTotal scan not ready after multiple attempts", "yellow"))
        else:
            print(colored("[!] Failed to submit URL to VirusTotal", 'yellow'))

    except Exception as e:
        print(colored(f"[!] VirusTotal error: {e}", "yellow"))