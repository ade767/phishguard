
import os
import requests
import ipaddress
import tldextract
from datetime import datetime, timezone
from urllib.parse import urlparse

API_KEY = os.environ.get("SAFE_BROWSING_API_KEY")

API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"


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


def get_domain_intelligence(domain):
    result = {
        "domain": domain,
        "registration_date": "Unavailable",
        "domain_age": "Unavailable",
        "registrar": "Unavailable",
        "expiry_date": "Unavailable",
        "status": "Unavailable"
    }

    try:
        # Find the correct RDAP server
        bootstrap = requests.get(
            RDAP_BOOTSTRAP_URL,
            timeout=15
        )
        bootstrap.raise_for_status()

        rdap_data = bootstrap.json()

        rdap_server = None
        domain_lower = domain.lower()

        for service in rdap_data.get("services", []):
            tlds, urls = service

            for tld in tlds:
                if domain_lower.endswith("." + tld.lower()) or domain_lower == tld.lower():
                    rdap_server = urls[0]
                    break

            if rdap_server:
                break

        if not rdap_server:
            return result

        # Query domain registration information
        response = requests.get(
            f"{rdap_server.rstrip('/')}/domain/{domain}",
            headers={"Accept": "application/rdap+json"},
            timeout=15
        )

        response.raise_for_status()
        data = response.json()

        # Registration and expiry dates
        for event in data.get("events", []):
            action = event.get("eventAction")
            date = event.get("eventDate")

            if action == "registration":
                registered = datetime.fromisoformat(
                    date.replace("Z", "+00:00")
                )

                result["registration_date"] = registered.strftime(
                    "%Y-%m-%d"
                )

                age = datetime.now(timezone.utc) - registered
                days = age.days

                if days < 0:
                    result["domain_age"] = "Invalid registration date"
                elif days < 30:
                    result["domain_age"] = f"{days} days"
                else:
                    years = days // 365
                    months = (days % 365) // 30
                    result["domain_age"] = (
                        f"{years} years, {months} months"
                        if years else f"{months} months"
                    )

            elif action == "expiration":
                result["expiry_date"] = date[:10]

        # Registrar
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [])

                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == "fn":
                            result["registrar"] = item[3]
                            break

                break

        # Domain status
        statuses = data.get("status", [])

        if statuses:
            result["status"] = ", ".join(statuses)

    except requests.RequestException as error:
        print("RDAP error:", error)

    except (ValueError, KeyError, TypeError, IndexError) as error:
        print("RDAP data error:", error)

    return result


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
                    
