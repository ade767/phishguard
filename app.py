
from flask import Flask, render_template, request, send_from_directory
from scanner import check_url, analyze_url, get_domain_intelligence
from urllib.parse import urlparse
import ipaddress

app = Flask(__name__)


@app.route("/service-worker.js")
def service_worker():
    return send_from_directory(
        "static",
        "service-worker.js",
        mimetype="application/javascript"
    )


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "").strip()

    result = check_url(url)
    warnings = analyze_url(url)

    parsed = urlparse(url)
    domain = parsed.hostname

    domain_intelligence = {
        "domain": "Unavailable",
        "registration_date": "Unavailable",
        "domain_age": "Unavailable",
        "registrar": "Unavailable",
        "expiry_date": "Unavailable",
        "status": "Unavailable"
    }

    if domain:
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            domain_intelligence = get_domain_intelligence(domain)

    return render_template(
        "result.html",
        url=url,
        result=result,
        warnings=warnings,
        domain_intelligence=domain_intelligence
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
    
