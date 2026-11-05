
import os
import requests

API_KEY = os.environ.get("SAFE_BROWSING_API_KEY")

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


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

        if data.get("matches"):
            return "DANGEROUS"

        return "NO KNOWN THREATS FOUND"

    except requests.RequestException as error:
        print("Google API error:", error)
        return "SCAN ERROR"
