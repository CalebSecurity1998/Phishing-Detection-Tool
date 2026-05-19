from flask import Flask, jsonify, render_template, request
from phishing_detector import detect_phishing

app = Flask(__name__)

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/analyze")
def analyze():
    payload = request.get_json(silent=True) or request.form

    text = (payload.get("text") or "").strip()
    subject = (payload.get("subject") or "").strip()
    sender = (payload.get("sender") or "").strip()
    url = (payload.get("url") or "").strip()
    raw_attachments = payload.get("attachments") or ""
    attachments = [item.strip() for item in raw_attachments.split(",") if item.strip()]

    if not any([text, subject, sender, url, attachments]):
        return jsonify({
            "error": "Provide email content, a subject, sender, attachment filename, or a URL to analyze."
        }), 400

    result = detect_phishing(
        text=text,
        subject=subject,
        sender=sender,
        attachments=attachments,
        url=url,
    )

    return jsonify(result.to_dict())

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(debug=True)
