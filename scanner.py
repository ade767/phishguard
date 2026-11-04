import os
import requests

API_KEY = os.environ.get("SAFE_BROWSING_API_KEY")

def check_url(url):

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    payload = {
        "client": {
            "clientId": "PhishGuard",
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
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(api_url, json=payload, timeout=15)
        response.raise_for_status()
        result = response.json()

        if result.get("matches"):
            return "DANGEROUS"

        return "NO KNOWN THREATS FOUND"

    except requests.RequestException:
        return "SCAN ERROR"