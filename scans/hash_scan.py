import requests
from termcolor import colored
from configparser import ConfigParser
import os

config = ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '..', 'API.config'))
VT_API_KEY = config.get("API_KEYS", "VT_API_KEY", fallback="")
HYBRID_API_KEY = config.get("API_KEYS", "HYBRID_API_KEY", fallback="")

def hash_scan(file_hash):
    print("🔍 Running Hash Scan...")
    print('')

    # VirusTotal
    print(colored('###### Virus Total Results ######', 'green'))
    vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(vt_url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        file_id = data.get("data", {}).get("id", file_hash)

        print('[+] Virus Total URL:', colored(f'https://www.virustotal.com/gui/file/{file_id}', 'red'))
        print('[+] SHA256:', attributes.get('sha256', 'N/A'))
        print('[+] MD5   :', attributes.get('md5', 'N/A'))
        print('[+] SHA1  :', attributes.get('sha1', 'N/A'))
        names = attributes.get('names', [])
        print('[+] File Name(s):', ', '.join(names[:3]) if names else 'N/A')
        stats = attributes.get("last_analysis_stats", {})
        print('[+] Malicious:', colored(stats.get('malicious', 0), 'red'))
        print('[+] Suspicious:', colored(stats.get('suspicious', 0), 'yellow'))
        print('[+] Harmless:', colored(stats.get('harmless', 0), 'green'))
        print('[+] Undetected:', stats.get('undetected', 0))
        print("")
    else:
        print(colored("[!] Failed to retrieve data from VirusTotal", 'yellow'))
        print("")

    print('')
    print(colored('###### Hybrid Analysis Results ######', 'green'))
    hybrid_url = f"https://www.hybrid-analysis.com/api/v2/overview/{file_hash}"
    headers = {
        'api-key': HYBRID_API_KEY,
        'User-Agent': 'Falcon Sandbox',
    }
    response = requests.get(hybrid_url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        sha256 = data.get("sha256", "N/A")
        file_name = data.get("last_file_name", "N/A")
        verdict = data.get("verdict", "N/A")
        threat_family = data.get("vx_family", "N/A")
        file_type = data.get("type", "N/A")
        threat_score = data.get("threat_score", "N/A")
        report_url = f"https://www.hybrid-analysis.com/sample/{sha256}"

        print('[+] Hybrid Analysis Report URL:', colored(report_url, 'red'))
        print('[+] SHA256:', sha256)
        print('[+] File Name:', file_name)
        print('[+] Verdict:', verdict)
        print('[+] Malware Family:', threat_family)
        print('[+] File Type:', file_type)
        print('[+] Threat Score:', threat_score)
        print("")
    elif response.status_code == 404:
        print("[-] No report found for the provided hash.")
        print("")
    else:
        print(f"[-] Hybrid Analysis API request failed. Status Code: {response.status_code}")
        print(f"[-] Response: {response.text}")
        print("")

    print('')
