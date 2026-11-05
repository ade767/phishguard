
import os
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

API_KEY = os.environ.get("SAFE_BROWSING_API_KEY")


def check_url(url):

    if not API_KEY:
        return "SCAN ERROR: API key missing"

    try:
        service = build(
            "safebrowsing",
            "v5",
            developerKey=API_KEY,
            cache_discovery=False
        )

        response = service.urls().search(
            urls=[url]
        ).execute()

        if response.get("threats"):
            return "DANGEROUS"

        return "NO KNOWN THREATS FOUND"

    except HttpError as error:
        print("Google API error:", error)
        return "SCAN ERROR"

    except Exception as error:
        print("Scanner error:", error)
        return "SCAN ERROR"
        
