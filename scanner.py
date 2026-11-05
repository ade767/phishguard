
import os
import requests

API_KEY = os.environ.get("SAFE_BROWSING_API_KEY")

API_URL = "https://safebrowsing.googleapis.com/v5/urls:search"


def check_url(url):

    if not API_KEY:
        return "SCAN ERROR: API key missing"

    params = {
        "key": API_KEY,
        "urls": url
        
    }

    try:
        response = requests.get(
            API_URL,
            params=params,
            timeout=15
        )

        response.raise_for_status()

        print("STATUS:", response.status_code)
        print("CONTENT TYPE:", response.headers.get("Content-Type"))
        print("RESPONSE:", 
         repr(response.text[:500]))

        data = response.json()
        

        if data.get("threats"):
            return "DANGEROUS"

        return "NO KNOWN THREATS FOUND"

    except requests.HTTPError as error:
        print("Google API HTTP error:", response.status_code)
        print("Google API response:", response.text)
        return "SCAN ERROR"

    except requests.RequestException as error:
        print("Request error:", error)
        return "SCAN ERROR"
        

