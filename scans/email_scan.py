import requests
from termcolor import colored
from configparser import ConfigParser
import os
from scans.domain_scan import domain_scan

# Load API key
config = ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '..', 'API.config'))
HUNTER_API_KEY = config.get("API_KEYS", "HUNTER_API_KEY", fallback="")

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

        # Extract domain from email and run domain scan
        domain = email.split("@")[-1]
        print(colored("###### Domain Scan Based on Email Domain ######", "green"))
        print("")
        domain_scan(domain)

    else:
        print(colored("[!] Hunter.io request failed", "yellow"))
