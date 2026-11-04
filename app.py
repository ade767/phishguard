from flask import Flask, render_template, request
from scanner import check_url

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url")
    result = check_url(url)

    return render_template(
        "result.html",
        url=url,
        result=result
    )
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
    