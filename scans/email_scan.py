import requests
from termcolor import colored
from configparser import ConfigParser
import os
from scans.domain_scan import domain_scan

# Load API key
config = ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '..', 'API.config'))
HUNTER_API_KEY = config.get("API_KEYS", "HUNTER_API_KEY", fallback="")
HIBP_API_KEY = config.get("API_KEYS", "HIBP_API_KEY", fallback="")

def email_scan(email):
    print("\U0001F50D Running Email Scan...")
    print("")

    if not HUNTER_API_KEY:
        print(colored("[!] Missing Hunter.io API key in API.config", "yellow"))
        return

    url = "https://api.hunter.io/v2/email-verifier"
    params = {
        "email": email,
        "api_key": HUNTER_API_KEY
    }

    response = requests.get(url, params=params)

    if response.status_code == 200:
        data = response.json().get("data", {})
        print(colored("###### Hunter.io Results ######", "green"))
        print("[+] Email:", colored(email, "blue"))
        print("[+] Status:", colored(data.get("status", "N/A"), "blue"))
        print("[+] Confidence Score:", colored(data.get("score", "N/A"), "blue"))
        print("[+] MX Records:", colored(data.get("mx_records", "N/A"), "blue"))
        print("[+] SMTP Ping Check:", colored(data.get("smtp_check", "N/A"), "blue"))
        print("[+] Account Is Disposable:", colored(data.get("disposable", "N/A"), "blue"))
        print("[+] Webmail Provider:", colored(data.get("webmail", "N/A"), "blue"))
        print("[+] Domain:", colored(data.get("domain", "N/A"), "blue"))
        print("")
    else:
        print(colored("[!] Hunter.io request failed", "yellow"))


    # === HIBP Section ===
    if not HIBP_API_KEY:
        print(colored("[!] Missing HIBP API key in API.config", "yellow"))
        return

    print(colored("###### Have I Been Pwned (HIBP) Results ######", "green"))
    hibp_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": "OSINT.py"
    }

    hibp_response = requests.get(hibp_url, headers=headers)

    if hibp_response.status_code == 200:
        breaches = hibp_response.json()
        print(f"[+] {email} found in {len(breaches)} breach(es):")
        print("")
        for breach in breaches:
            breach_name = breach.get('Name')
            breach_date = 'Unknown'

            breach_detail_url = f"https://haveibeenpwned.com/api/v3/breach/{breach_name}"
            detail_response = requests.get(breach_detail_url, headers=headers)

            if detail_response.status_code == 200:
                details = detail_response.json()
                breach_date = details.get('BreachDate', 'Unknown')
                data_classes = ', '.join(details.get('DataClasses', []))
                print(f"- {colored(breach_name, 'red')} [{colored(breach_date, 'blue')}]")
                print(f"   Data Involved: {colored(data_classes, 'blue')}")
                print(f"   Link to Details: {colored(f'https://haveibeenpwned.com/PwnedWebsites#{breach_name}', 'blue')}")
                
            else:
                print(colored(f"   [!] Failed to retrieve full details for {breach_name}", "yellow"))
        print("")
    elif hibp_response.status_code == 404:
        print(colored(f"[!] No breaches found for {email}", "yellow"))
        print("")
    else:
        print(colored(f"[!] HIBP request failed ({hibp_response.status_code})", "yellow"))
        print("")


    # Extract domain from email and run domain scan
    domain = email.split("@")[-1]
    print(colored("###### Domain Scan Based on Email Domain ######", "green"))
    print("")
    domain_scan(domain)


