# Phishing Detection Tool

A lightweight, explainable web application for identifying common phishing indicators in email content, URLs, and attachment filenames.

The tool assigns a phishing risk score from **0 to 100** and explains which indicators contributed to the score. It is designed for cybersecurity demonstrations, analyst triage, awareness training, and portfolio projects.

---

## Features

- Analyze suspicious **email subjects**, **senders**, and **message bodies**
- Inspect standalone **URLs** for phishing-style patterns
- Flag risky **attachment filenames**
- Generate an explainable **risk score**
- Categorize results as:
  - Minimal
  - Low
  - Medium
  - High
- Display clear findings in a responsive browser interface
- Includes a built-in **demo sample**
- Ready to deploy on **Render**
- Includes a `/healthz` endpoint for deployment health checks

---

## How It Works

The detector uses rule-based heuristics to identify common phishing signals, including:

### Email Indicators

- Urgent or high-pressure language
- Requests to verify credentials or reset passwords
- Financial or payment-related wording
- Threatening language
- Generic greetings
- Excessive capitalization or punctuation
- Suspicious sender naming patterns
- Risky attachment extensions

### URL Indicators

- Raw IP addresses instead of domains
- HTTP links instead of HTTPS
- URL shorteners
- Punycode domains
- Excessive subdomains
- Multiple hyphens in domains
- Login, verification, or account-related terms in paths
- Very long or heavily encoded URLs

### Compound Rules

The scoring model also boosts risk when suspicious signals appear together, such as:

- Urgency + credential request
- Urgency + payment request
- Credential request + link

---

## Tech Stack

- **Python**
- **Flask**
- **Gunicorn**
- **HTML**
- **CSS**
- **Vanilla JavaScript**
- **Render** for deployment

---

## Project Structure

```text
phishing-detector-render/
├── app.py
├── phishing_detector.py
├── requirements.txt
├── render.yaml
├── README.md
├── templates/
│   └── index.html
└── static/
    └── styles.css
