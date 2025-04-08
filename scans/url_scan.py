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
            print('[+] ' + f"{key}: {colored(value, 'blue')}")
        print("")
    except:
        print(colored("[!] WHOIS lookup failed", "yellow"))
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
    data = {"url": url, "visibility": "public"}
    try:
        response = requests.post("https://urlscan.io/api/v1/scan/", json=data, headers=headers)
        if response.status_code == 200:
            scan_id = response.json().get("uuid")
            print(f"[+] Scan submitted! ID:", colored(scan_id, 'blue'))
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
                print("[+] Page Title:", colored(result_data.get("page", {}).get("title", "N/A"), "blue"))
                print("[+] Domain:", colored(result_data.get("page", {}).get("domain", "N/A"), "blue"))
                print("[+] IP:", colored(result_data.get("page", {}).get("ip", "N/A"), "blue"))
                print("[+] Country:", colored(country_name, "blue"))
                print("[+] URL:", colored(result_data.get("page", {}).get("url", "N/A"), "blue"))
                print("[+] Report URL:", colored(result_data.get("task", {}).get("reportURL", "N/A"), "blue"))
                print("[+] Screenshot URL:", colored(result_data.get("task", {}).get("screenshotURL", "N/A"), "blue"))
                print("[+] Verdict Score:", colored(result_data.get("verdicts", {}).get("overall", {}).get("score", "N/A"), "blue"))
                print("[+] Domain is Malicious:", colored(result_data.get("verdicts", {}).get("overall", {}).get("malicious", "N/A"), "blue"))
                print("")
        else:
            print(colored("[!] URLScan.io scan request failed", "yellow"))
            print("")
    except Exception as e:
        print(colored(f"[!] URLScan.io error: {e}", "yellow"))
        print("")

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
                    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
                    gui_url = f'https://www.virustotal.com/gui/url/{encoded_url}'
                    stats = data.get("data", {}).get("attributes", {}).get("stats", {})
                    print('[+] Virus Total Analysis ID:', colored(analysis_id, 'blue'))
                    print('[+] VirusTotal Report URL:', colored(gui_url, 'blue'))
                    print('[+] Malicious Reports:', colored(stats.get('malicious', 0), 'red'))
                    print('[+] Suspicious Reports:', colored(stats.get('suspicious', 0), 'yellow'))
                    print('[+] Harmless Reports:', colored(stats.get('harmless', 0), 'green'))
                    print('[+] Undetected Reports:', colored(stats.get('undetected', 0), 'blue'))
                    print("")
                    break
                else:
                    print(f"[!] Attempt {attempt + 1}: VirusTotal scan still processing...")
            else:
                print(colored("[!] VirusTotal scan not ready after multiple attempts", "yellow"))
                print("")
        else:
            print(colored("[!] Failed to submit URL to VirusTotal", 'yellow'))
            print("")

    except Exception as e:
        print(colored(f"[!] VirusTotal error: {e}", "yellow"))

    # URLHaus
    print(colored('###### URLHaus Results ######', 'green'))
    try:
        urlhaus_api = "https://urlhaus.abuse.ch/api/"
        normalized_url = url.replace('https://', 'http://').rstrip('/')
        urlhaus_data = {"url": normalized_url, "query": "get_url"}
        stripped_host = parsed_url.hostname
        urlhaus_response = requests.post(urlhaus_api, data=urlhaus_data)

        if urlhaus_response.status_code == 200:
            if urlhaus_response.text.strip():
                urlhaus_result = urlhaus_response.json()
                status = urlhaus_result.get("query_status")
                if status == "ok":
                    print('[+] URL:', colored(urlhaus_result.get("url", "N/A"), 'blue'))
                    print('[+] Host:', colored(urlhaus_result.get("host", "N/A"), 'blue'))
                    print('[+] Date Added:', colored(urlhaus_result.get("date_added", "N/A"), 'blue'))
                    print('[+] Threat:', colored(urlhaus_result.get("threat", "N/A"), 'blue'))
                    print('[+] Reporter:', colored(urlhaus_result.get("reporter", "N/A"), 'blue'))
                    print('[+] Tags:', colored(", ".join(urlhaus_result.get("tags", [])), 'blue'))
                    payloads = urlhaus_result.get("payloads", [])
                    if payloads:
                        print('[+] Payloads:')
                        for payload in payloads:
                            print(f"    - Filename: {payload.get('filename', 'N/A')}")
                            print(f"      File Type: {payload.get('file_type', 'N/A')}")
                            print(f"      MD5 Hash: {payload.get('file_hash', 'N/A')}")
                            print(f"      Signature: {payload.get('signature', 'N/A')}")
                    print("")
                elif status == "no_results":
                    print(colored("[-] URL not found in URLHaus database", 'yellow'))
                    # Retry with host-only
                    print(colored("[*] Retrying with host-only search...", 'cyan'))
                    urlhaus_data = {"host": domain, "query": "get_host"}
                    urlhaus_response = requests.post(urlhaus_api, data=urlhaus_data)
                    if urlhaus_response.status_code == 200 and urlhaus_response.text.strip():
                        urlhaus_result = urlhaus_response.json()
                        if urlhaus_result.get("query_status") == "ok":
                            print('[+] Host:', colored(urlhaus_result.get("host", "N/A"), 'blue'))
                            urls = urlhaus_result.get("urls", [])
                            print('[+] URL Count:', colored(len(urls), 'blue'))
                            print('[+] Recent URLs:')
                            for entry in urls[:3]:
                                print(f"    - {entry.get('url', 'N/A')} ({entry.get('threat', 'N/A')})")
                        else:
                            print(colored("[-] No host-level match in URLHaus either", 'yellow'))
                else:
                    print(colored(f"[-] Unexpected URLHaus status: {status}", 'yellow'))
            else:
                print(colored("[!] Empty response from URLHaus", 'yellow'))
        else:
            print(colored("[!] URLHaus API request failed", 'yellow'))
    except Exception as e:
        print(colored(f"[!] URLHaus error: {e}", 'yellow'))
        print("")