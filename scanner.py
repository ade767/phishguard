
import os
import requests
import ipaddress
from urllib.parse import urlparse

API_KEY = os.environ.get("SAFE_BROWSING_API_KEY")

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def analyze_url(url):
    warnings = []

    parsed = urlparse(url)
    domain = parsed.hostname

    if not domain:
        warnings.append("Invalid URL")
        return warnings

    try:
        ipaddress.ip_address(domain)
        warnings.append("URL uses an IP address")
    except ValueError:
        pass

    if "@" in url:
        warnings.append("URL contains an @ symbol")

    if len(url) > 100:
        warnings.append("Unusually long URL")

    if len(domain.split(".")) > 4:
        warnings.append("Excessive subdomains")

    return warnings



def check_url(url):
    if not API_KEY:
        return "SCAN ERROR: API key missing"

    params = {"key": API_KEY}

    payload = {
        "client": {
            "clientId": "phishguard",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        response = requests.post(
            API_URL,
            params=params,
            json=payload,
            timeout=15
        )

        response.raise_for_status()
        data = response.json()

        matches = data.get("matches", [])

        if matches:
            threat_types = list(set(
                match.get("threatType", "UNKNOWN")
                for match in matches
            ))

            return ", ".join(threat_types)

        return "NO KNOWN THREATS FOUND"

    except requests.RequestException as error:
        print("Google API error:", error)
        return "SCAN ERROR"
        
