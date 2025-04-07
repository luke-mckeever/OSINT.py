# OSINT.py
The general consensus is that open source intellegence shouldn't be hard 

Please stay tuned for my amazing OSINT tool nicknamed OSINT.py

This tool intends to query the following DB's:
- Virus Total
- URLScan.io
- Hybrid Analysis
- Malware Bazar (Not Implemented)
- AbuseIPDB
- Hunter.io
- CloudFlare Radar (Not Implemented)
- ChatGPT (eventually)

Pre-requesites:
As This will requires the appropriate tooling API, personal API keys are required,
These will be insertable into the API.config file, and any missing API's will just be skipped
Python 3 is also required


## Getting Started

Use the following command to install the required libraries

```bash
pip install -r requirements.txt
```


The intended outcome of this tool is the following 

1. Accept input of an IOC of eother domain, URL, IP or email 
2. preform API calls for from the listed sources based on the provided IOC
3. Verify IOC Type and preform the appropriate API calls:
  - Virus Total (if IOC of type: File Hash, IP, URL or Domain)
      If the IOC type is not within the accepted list if will not preform any API calls from Virus total
      If the IOC type is within the accepted list & previous scans of IOC exist preform API call for given IOC and return results (no need to further submit)
      If no previous scans of IOC exist submit the IOC to virus total to preform analysis
      If IOC has been submitted to Virus total, preform API call and return results
  - URLscan.io (if IOC of type: URL or Domain)
      If the IOC type is not within the accepted list if will not preform any API calls from URLScan.io
      If the IOC type is within the accepted list & previous scans of IOC exist preform API call for given IOC and return results (no need to further submit)
      If no previous scans of IOC exist submit the IOC to URLScan.io to preform analysis
      If IOC has been submitted to URLScan.io, preform API call and return results
  - Hybrid Analysis (if IOC of type: File Hash)
      If the IOC type is not within the accepted list if will not preform any API calls from Hybrid Analysis
      If the IOC type is within the accepted list & previous scans of IOC exist preform API call for given IOC and return results (no need to further submit)
      If no previous scans of IOC exist submit the IOC to Hybrid Analysis to preform analysis
      If IOC has been submitted to Hybrid Analysis, preform API call and return results
  - AbuseIPDB (if IOC of type: IP)
      If the IOC type is not within the accepted list if will not preform any API calls from AbuseIPDB
      If the IOC type is within the accepted list return results
  - DNS Lookup (if IOC of type: Domain, URL or IP)
      If the IOC type is not within the accepted list if will not preform a DNS lookup
      If the IOC type is within the accepted list return results
  - Reverse DNS Lookup (if IOC of type: Domain, URL or IP)
      If the IOC type is not within the accepted list if will not preform a reverse DNS lookup
      If the IOC type is within the accepted list return results
  - Hunter.io (if IOC of type: email)
      If the IOC type is not within the accepted list if will not preform any API calls from Hunter.io
      If the IOC type is within the accepted list & previous scans of IOC exist preform API call for given IOC and return results (no need to further submit)
      If no previous scans of IOC exist submit the IOC to Hunter.io to preform analysis
      If IOC has been submitted to Hunter.io, preform API call and return results
4. Display all relevent information in an elegant way upon copmpletion of the script

    
  - Coming Soon: Chat GPT (if IOC of type: any)
      Intended outcome: 
        If the IOC type is not within the accepted list if will not preform any API calls from ChatGPT
        If the IOC type is within the accepted list submit the IOC to ChatGPT with the provided role and promt 
          Potential Prompt: 
          Role:"All incoming prompt's are singular IOC's (Indicators of Compramise) your task is to accept, assess and evaluate these IOC's snd provide a score of maliciousness out of 100 upon completion, please provide your full analysis when responding."
          Prompt: "The Potential IOC is: + <Input Variable> 
        If IOC has been submitted to ChatGPT, preform API call and return results

The above is a rudamentary list that will be able to preform the neccesary research required of any profesional in their field
