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
    sha256_hash = None
    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        sha256_hash = attributes.get("sha256", None)
        md5_hash = attributes.get("md5", "N/A")
        sha1_hash = attributes.get("sha1", "N/A")
        file_names = attributes.get("names", [])
        file_names_str = ", ".join(file_names) if file_names else "N/A"

        print('[+] Virus Total URL:', colored(f'https://www.virustotal.com/gui/file/{sha256_hash}', 'blue'))
        print('[+] SHA256:', colored(sha256_hash, 'blue'))
        print('[+] MD5   :', colored(md5_hash, 'blue'))
        print('[+] SHA1  :', colored(sha1_hash, 'blue'))
        print('[+] File Name(s):', colored(file_names_str, 'blue'))
        print('[+] Malicious:', colored(stats.get('malicious', 0), 'red'))
        print('[+] Suspicious:', colored(stats.get('suspicious', 0), 'yellow'))
        print('[+] Harmless:', colored(stats.get('harmless', 0), 'green'))
        print('[+] Undetected:', colored(stats.get('undetected', 0), 'blue'))
        print("")
    else:
        print(colored("[!] VirusTotal lookup failed", 'yellow'))
        print("")

    # Hybrid Analysis (Rewritten)
    print(colored('###### Hybrid Analysis Results ######', 'green'))
    
    hybrid_url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    headers = {
        "api-key": HYBRID_API_KEY,
        "User-Agent": "Falcon Sandbox",
        "Content-Type": "application/json"
    }
    payload = {"hash": sha256_hash}
    response = requests.post(hybrid_url, headers=headers, json={"hash": sha256_hash})

    if response.status_code == 200:
        results = response.json()
        if results:
            first_result = results[0]
            print('[+] SHA256:', colored(sha256_hash, 'blue'))
            print('[+] Threat Score:', colored(first_result.get("threat_score", "N/A"), 'blue'))
            print('[+] Verdict:', colored(first_result.get("verdict", "N/A"), 'blue'))
            print('[+] Scan Link:', colored(f'https://www.hybrid-analysis.com/sample/{sha256_hash}', 'blue'))
            print("")
        else:
            print(colored('[!] No results found on Hybrid Analysis', 'yellow'))
            print("")
    else:
        print(colored(f'[!] Hybrid Analysis lookup failed with status code {response.status_code}', 'yellow'))
        print("")

    # MalwareBazaar
    print(colored('###### MalwareBazaar Results ######', 'green'))
    mb_url = "https://mb-api.abuse.ch/api/v1/"
    mb_payload = {
        "query": "get_info",
        "hash": file_hash
    }
    try:
        mb_response = requests.post(mb_url, data=mb_payload)
        if mb_response.status_code == 200:
            mb_data = mb_response.json()
            if mb_data.get("query_status") == "ok":
                result = mb_data["data"][0]
                hash_result = result.get("sha256_hash", "N/A")
                print('[+] SHA256:', colored(hash_result, 'blue'))
                print('[+] File Type:', colored(result.get("file_type", "N/A"), 'blue'))
                print('[+] Signature:', colored(result.get("signature", "N/A"), 'blue'))
                print('[+] Delivery Method:', colored(result.get("delivery_method", "N/A"), 'blue'))
                print('[+] Reporter:', colored(result.get("reporter", "N/A"), 'blue'))
                print('[+] First Seen:', colored(result.get("first_seen", "N/A"), 'blue'))
                print('[+] Tags:', colored(", ".join(result.get("tags", [])), 'blue'))
                print('[+] Sample URL:', colored('https://bazaar.abuse.ch/sample/' + hash_result, 'blue'))
            else:
                print(colored(f"[-] No results found on MalwareBazaar for hash: {file_hash}", "yellow"))
        else:
            print(colored("[!] MalwareBazaar API request failed", "red"))
    except Exception as e:
        print(colored(f"[!] Error querying MalwareBazaar: {e}", "red"))