# Phishing Detection Web App

A Render-ready Flask web app that scores phishing risk using explainable email and URL heuristics.

## Project structure

```text
.
├── app.py
├── phishing_detector.py
├── requirements.txt
├── render.yaml
├── templates/
│   └── index.html
└── static/
    └── styles.css
```

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000`.

## Deploy to Render

1. Push this folder to a GitHub repository.
2. In Render, create a new **Web Service** from that repository.
3. Render can read `render.yaml`, or you can manually set:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`
4. Deploy.

The app also exposes `/healthz` for Render health checks.
