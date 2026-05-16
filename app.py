from flask import Flask, render_template, request
from analyzer import analyze_email
from database import save_scan, get_history

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        sender = request.form.get("sender", "")
        subject = request.form.get("subject", "")
        body = request.form.get("body", "")

        result = analyze_email(sender, subject, body)

        save_scan(sender, subject, result["score"], result["risk_level"])

        return render_template(
            "result.html",
            result=result,
            sender=sender,
            subject=subject,
            body=body
        )

    return render_template("index.html")

@app.route("/history")
def history():
    scans = get_history()
    return render_template("history.html", scans=scans)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)