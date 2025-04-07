
#####Imports
import requests
import socket
import whois
import pycountry
import time
import base64
from urllib.parse import urlparse
from termcolor import colored

#####API Keys
# API keys (Replace with your own keys)
VT_API_KEY = ""
URLSCAN_API_KEY = ""
ABUSEIPDB_API_KEY = ""
HUNTER_API_KEY = ""
HYBRID_API_KEY = ""

print(colored('Welcome To...', 'blue'))
print(colored(' ██████╗ ███████╗██╗███╗   ██╗████████╗██████╗ ██╗   ██╗', 'red'))
print(colored('██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝', 'red'))
print(colored('██║   ██║███████╗██║██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝', 'red'))
print(colored('██║   ██║╚════██║██║██║╚██╗██║   ██║   ██╔═══╝   ╚██╔╝  ', 'red'))
print(colored('╚██████╔╝███████║██║██║ ╚████║   ██║██╗██║        ██║   ', 'red'))
print(colored(' ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝╚═╝╚═╝        ╚═╝   ', 'red'))
print(colored('Ver 0.2.1, Brought to you by Luke McKeever', 'blue'))
print(colored('╔════════════════════════════════════════════════════════════════════╗', 'red'))
print(colored('║  1. IP Scan - (WhoIs, Reverse Lookup, AbuseIPDB, Virus Total )     ║', 'red'))
print(colored('║  2. Domain Scan - (WhoIs, Reverse Lookup, URLScan.io, Virus Total) ║', 'red'))
print(colored('║  3. URL Scan - (WhoIs, Reverse Lookup, URLScan.io, VirusTotal)     ║', 'red'))
print(colored('║  4. Hash Scan - (Virus Total, Hybrid Analysis)                     ║', 'red'))
print(colored('║  5. Email Scan                                                     ║', 'red'))
print(colored('║  6. Account Scan                                                   ║', 'red'))
print(colored('╚════════════════════════════════════════════════════════════════════╝', 'red'))

######### GET COUNTRY METHOD ####################
def get_country_name(country_code):
    country = pycountry.countries.get(alpha_2=country_code)
    return country.name if country else 'Unknown'


########## IP Scan Method ##########################
def ip_scan():
    IOC = input(colored('IP Scan Selected, Please enter IOC IP: ', 'blue')).strip()
    print("")
    print("🔍 Running IP Scan...")
    ######Who Is Lookup
    print(colored('###### Who Is Results ######', 'green'))
    whoarray = (whois.whois(IOC)) 
    for key, value in whoarray.items():
      print('[+] ' + f"{key}: {colored(value, 'red')}")
    print('')
    ############################
    ######Reverse IP Lookup
    print(colored ('###### Reverse IP Lookup ######', 'green'))
    try:
      rev = socket.gethostbyaddr(IOC)
      out = rev[0]
      print('[+] This IP resolves to: ' + colored(out, 'red'))
    except:
      print(colored('[+] IP is not resolvable', 'yellow')) 
      print('')
    ###########################
    ######Abuse IPDB Scan
    print('')
    print(colored('###### Abuse IPDB Results #######', 'green'))
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": IOC,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params)
    aipdb_result = (response.json() if response.status_code == 200 else {"error": "Failed to retrieve data from AbuseIPDB"})
    d = aipdb_result['data']
    country_name = get_country_name(d['countryCode'])

    print(f"[+] IP Address: {colored(d['ipAddress'], 'red')}")
    print(f"[+] Is Address Whitelisted: {colored('Yes' if d['isWhitelisted'] else 'No', 'red')}")
    print(f"[+] Country Code: {colored(d['countryCode'], 'red')}")
    print(f"[+] Country Name: " + colored(country_name, 'red'))
    print(f"[+] Domain: {colored(d['domain'], 'red')}")
    print(f"[+] Total Reports: {colored(d['totalReports'], 'red')}")
    print(f"[+] Last Reported At: {colored(d['lastReportedAt'], 'red')}")
    print('')
    ###########################
    ######Virus Total Results
    print(colored('###### Virus Total Results ######', 'green'))
    
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{IOC}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()

        print('[+] Virus Total URL: ' + colored(url, 'red'))
        hits = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if hits:
            print('[+]' , colored(f"Malicious: {hits.get('malicious', 0)}", "red"))
            print('[+]' , colored(f"Suspicious: {hits.get('suspicious', 0)}", "yellow"))
            print('[+]' , colored(f"Harmless: {hits.get('harmless', 0)}", "green"))
            print('[+] Undetected:' , hits.get('undetected', 0))
    else:
        print("error-Failed to retrieve data from VirusTotal")
    ############################
    exit()

########## Domain Scan Method ######################
def domain_scan():
    IOC = input(colored('Domain Scan Selected, Please enter a domain: ', 'blue')).strip()
    print("🔍 Running Domain Scan...")
    print('')
    ######Who Is Lookup
    print(colored('###### Who Is Results ######', 'green'))
    whoarray = (whois.whois(IOC)) 
    for key, value in whoarray.items():
      print('[+] ' + f"{key}: {colored(value, 'red')}")
    print('')
    ############################
    ######Reverse DNS Lookup
    print(colored ('###### Reverse DNS Lookup ######', 'green'))
    try:
      dns = socket.gethostbyaddr(IOC)
      out = dns[0]
      print('[+] This domain resolves to: ' + colored(out, 'red'))
      print('')
    except:
      print(colored('[+] Domain is not resolvable', 'yellow')) 
      print('')
    ############################
    ########URLScan.io Lookup
    print(colored('###### URLScan.io Results ######', 'green'))
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    data = {"url": f"http://{IOC}", "visibility": "public"}
    try:
        response = requests.post("https://urlscan.io/api/v1/scan/", json=data, headers=headers)
        if response.status_code == 200:
            result = response.json()
            scan_id = result.get("uuid")
            print('[+] URLScan.io Scan Submitted! Scan ID:', scan_id)
            print('[+] Waiting for results... (Please allow up to 10 secconds for results)')
            time.sleep(15)  # Allow some time for the scan to complete

            result_response = requests.get(f"https://urlscan.io/api/v1/result/{scan_id}/")
            if result_response.status_code == 200:
                result_data = result_response.json()
                country_name = get_country_name(result_data.get("page", {}).get("country", "N/A"))
                print("[+] Page Title:", colored(result_data.get("page", {}).get("title", "N/A"), "red"))
                print("[+] Domain:", colored(result_data.get("page", {}).get("domain", "N/A"), "red"))
                print("[+] IP:", colored(result_data.get("page", {}).get("ip", "N/A"), "red"))
                print("[+] ASN:", colored(result_data.get("page", {}).get("asn", "N/A"), "red"))
                print("[+] Country:", colored(country_name, "red"))
                print("[+] URL:", colored(result_data.get("page", {}).get("url", "N/A"), "red"))
                print("[+] Report URL:", colored(result_data.get("task", {}).get("reportURL", "N/A"), "red"))
                print("[+] Screenshot URL:", colored(result_data.get("task", {}).get("screenshotURL", "N/A"), "red")) 
                print("[+] Verdict Score:", colored(result_data.get("verdicts", {}).get("overall", {}).get("score", "N/A"), "red"))
                print("[+] Domain is Malicious:", colored(result_data.get("verdicts", {}).get("overall", {}).get("malicious", "N/A"), "red"))
            else:
                print(colored(f"[!] Failed to retrieve scan result: {result_response.status_code}", "yellow"))
        else:
            print(colored(f"[!] URLScan.io error {response.status_code}: {response.text}", "yellow"))
    except Exception as e:
        print(colored(f"[!] URLScan.io query failed: {e}", "yellow"))
    print('')
    ###########################
    ######Virus Total Results
    print(colored('###### Virus Total Results ######', 'green'))
    
    
    url = f"https://www.virustotal.com/api/v3/domains/{IOC}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        
        print('[+] Virus Total URL: ' + colored(url, 'red'))
        hits = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if hits:
            print('[+]' , colored(f"Malicious: {hits.get('malicious', 0)}", "red"))
            print('[+]' , colored(f"Suspicious: {hits.get('suspicious', 0)}", "yellow"))
            print('[+]' , colored(f"Harmless: {hits.get('harmless', 0)}", "green"))
            print('[+] Undetected:' , hits.get('undetected', 0))
    else:
        print("error-Failed to retrieve data from VirusTotal")
    print('')
    ############################


def url_scan():
    IOC = input(colored('URL Scan Selected, Please enter a URL: ', 'blue')).strip()
    print("🔍 Running URL Scan...")
    print('')
    ######Who Is Lookup
    print(colored('###### Who Is Results ######', 'green'))
    parsed_url = urlparse(IOC)
    domain = parsed_url.netloc
    whoarray = (whois.whois(domain)) 
    for key, value in whoarray.items():
      print('[+] ' + f"{key}: {colored(value, 'red')}")
    print('')
    ############################
    ######Reverse DNS Lookup
    print(colored ('###### Reverse DNS Lookup ######', 'green'))
    parsed_url = urlparse(IOC)
    domain = parsed_url.netloc
    try:
      dns = socket.gethostbyaddr(domain)
      out = dns[0]
      print('[+] This domain resolves to: ' + colored(out, 'red'))
      print('')
    except:
      print(colored('[+] Domain is not resolvable', 'yellow')) 
      print('')
    ####################################################
    ########URLScan.io Lookup
    print(colored('###### URLScan.io Results ######', 'green'))
    headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
    data = {"url": f"{IOC}", "visibility": "public"}
    try:
        response = requests.post("https://urlscan.io/api/v1/scan/", json=data, headers=headers)
        if response.status_code == 200:
            result = response.json()
            scan_id = result.get("uuid")
            print('[+] URLScan.io Scan Submitted! Scan ID:', scan_id)
            print('[+] Waiting for results... (Please allow up to 10 secconds for results)')
            time.sleep(15)  # Allow some time for the scan to complete

            result_response = requests.get(f"https://urlscan.io/api/v1/result/{scan_id}/")
            if result_response.status_code == 200:
                result_data = result_response.json()
                country_name = get_country_name(result_data.get("page", {}).get("country", "N/A"))
                print("[+] Page Title:", colored(result_data.get("page", {}).get("title", "N/A"), "red"))
                print("[+] Domain:", colored(result_data.get("page", {}).get("domain", "N/A"), "red"))
                print("[+] IP:", colored(result_data.get("page", {}).get("ip", "N/A"), "red"))
                print("[+] ASN:", colored(result_data.get("page", {}).get("asn", "N/A"), "red"))
                print("[+] Country:", colored(country_name, "red"))
                print("[+] URL:", colored(result_data.get("page", {}).get("url", "N/A"), "red"))
                print("[+] Report URL:", colored(result_data.get("task", {}).get("reportURL", "N/A"), "red"))
                print("[+] Screenshot URL:", colored(result_data.get("task", {}).get("screenshotURL", "N/A"), "red")) 
                print("[+] Verdict Score:", colored(result_data.get("verdicts", {}).get("overall", {}).get("score", "N/A"), "red"))
                print("[+] Domain is Malicious:", colored(result_data.get("verdicts", {}).get("overall", {}).get("malicious", "N/A"), "red"))
            else:
                print(colored(f"[!] Failed to retrieve scan result: {result_response.status_code}", "yellow"))
        else:
            print(colored(f"[!] URLScan.io error {response.status_code}: {response.text}", "yellow"))
    except Exception as e:
        print(colored(f"[!] URLScan.io query failed: {e}", "yellow"))
    print('')
    ########################################
    ######Virus Total Results
    print(colored('###### Virus Total Results ######', 'green'))
    encoded_url = base64.urlsafe_b64encode(IOC.encode()).decode().strip("=")
    
    url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        print('[+] Virus Total URL: ' + colored('https://www.virustotal.com/gui/url/'+encoded_url, 'red'))
        hits = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if hits:
            print('[+]' , colored(f"Malicious: {hits.get('malicious', 0)}", "red"))
            print('[+]' , colored(f"Suspicious: {hits.get('suspicious', 0)}", "yellow"))
            print('[+]' , colored(f"Harmless: {hits.get('harmless', 0)}", "green"))
            print('[+] Undetected:' , hits.get('undetected', 0))
        else:
            print("error-Failed to retrieve data from VirusTotal")
    print('')
    ############################

def email_scan():
    print("Coming Soon")


def hash_scan():
    IOC = input(colored('Hash Scan Selected, Please enter a file hash: ', 'blue')).strip()
    print("🔍 Running Domain Scan...")
    print('')
    ######Virus Total Results
    print(colored('###### Virus Total Results ######', 'green'))
    
    url = f"https://www.virustotal.com/api/v3/files/{IOC}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        file_id = data.get("data", {}).get("id", IOC)

        print('[+] Virus Total URL: ' + colored(f'https://www.virustotal.com/gui/file/{file_id}', 'red'))
        print('[+] SHA256:', attributes.get('sha256', 'N/A'))
        print('[+] MD5   :', attributes.get('md5', 'N/A'))
        print('[+] SHA1  :', attributes.get('sha1', 'N/A'))
        file_names = attributes.get('names', [])
        if file_names:
          print('[+] File Name(s):', ', '.join(file_names[:3]))
        else:
          print('[+] File Name(s): N/A')
        hits = attributes.get("last_analysis_stats", {})
        print('[+]' , colored(f"Malicious: {hits.get('malicious', 0)}", "red"))
        print('[+]' , colored(f"Suspicious: {hits.get('suspicious', 0)}", "yellow"))
        print('[+]' , colored(f"Harmless: {hits.get('harmless', 0)}", "green"))
        print('[+] Undetected:' , hits.get('undetected', 0))
    else:
      print("error-Failed to retrieve data from VirusTotal")
    print('')
    ############################
    ######Hybrid Analysis scan
    BASE_URL = "https://www.hybrid-analysis.com/api/v2/search/hash"

    print(colored('###### Hybrid Analysis Results ######', 'green'))
    headers = {
        'api-key': HYBRID_API_KEY,
        'User-Agent': 'Falcon Sandbox',
    }

    headers = {
        'api-key': HYBRID_API_KEY,
        'User-Agent': 'Falcon Sandbox',
    }

    url = f"https://www.hybrid-analysis.com/api/v2/overview/{IOC}"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        sha256 = data.get("sha256", "N/A")
        file_name = data.get("last_file_name", "N/A")
        verdict = data.get("verdict", "N/A")
        threat_family = data.get("vx_family", "N/A")
        file_type = data.get("type", "N/A")
        threat_score = data.get("threat_score", "N/A")
        hybrid_url = f"https://www.hybrid-analysis.com/sample/{sha256}"

        print('[+] Hybrid Analysis Report URL:', colored(hybrid_url, 'red'))
        print('[+] SHA256:', sha256)
        print('[+] File Name(s):', file_name)
        print('[+] Verdict:', verdict)
        print('[+] Malware Family:', threat_family)
        print('[+] File Type:', file_type)
        print('[+] Threat Score:', threat_score)

    elif response.status_code == 404:
        print("[-] No report found for the provided hash.")
    else:
        print(f"[-] Hybrid Analysis API request failed. Status Code: {response.status_code}")
        print(f"[-] Response: {response.text}")

    print('')



def account_scan():
    print("Coming Soon")

def main():
    choice = input(colored('Please Select IOC Scan Type (1-5): ', 'blue')).strip()
    if choice == "1":
        ip_scan()
    elif choice == "2":
        domain_scan()
    elif choice == "3":
        url_scan()
    elif choice == "4":
        hash_scan()
    elif choice == "5":
        email_scan()
    elif choice == "6":
        account_scan()
    else:
        print("❌ Invalid choice. Please select a number between 1 and 6.")

main()

