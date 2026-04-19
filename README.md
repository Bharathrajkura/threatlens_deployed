# 🔍 ThreatLens — AI-Based Cyber Threat Detection

A full-stack web application that analyzes any URL through a 3-stage AI pipeline to determine if it's safe or malicious.

---

## 🏗 Architecture

```
Frontend (HTML/CSS/JS)       Backend (Flask + SQLite)
─────────────────────        ──────────────────────────────────
Login / Register        →    Flask Auth (Flask-Login + Bcrypt)
URL Input Dashboard     →    /api/analyze endpoint
Results + History            SQLite DB (users + search history)
                                  │
                             ┌────▼──────────────────────────┐
                             │   3-Stage Analysis Pipeline    │
                             │                                │
                             │  Stage 1: ML Analyzer          │
                             │  • URL length, entropy         │
                             │  • Phishing keywords           │
                             │  • RandomForest (UCI dataset)  │
                             │                                │
                             │  Stage 2: NLP Analyzer         │
                             │  • Fetches actual page         │
                             │  • TF-IDF + LogisticRegression │
                             │  • Urgency/credential language │
                             │  • Hidden iframes, forms       │
                             │                                │
                             │  Stage 3: API Analyzer         │
                             │  • VirusTotal v3 API           │
                             │  • AbuseIPDB API               │
                             │                                │
                             │  Score Normalizer              │
                             │  • Weighted average (30/30/40) │
                             │  • Final verdict + confidence  │
                             └────────────────────────────────┘
```

---

## ⚡ Quick Start (Any Computer)

### Windows
```
Double-click  run.bat
```
Then open: **http://localhost:5000**

### Mac / Linux
```bash
chmod +x run.sh
./run.sh
```
Then open: **http://localhost:5000**

### Manual (if scripts don't work)
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run
python app.py
```

---

## 📁 Project Structure

```
threatlens/
├── app.py                    ← Flask app, routes, DB models
├── requirements.txt          ← All Python dependencies
├── run.bat                   ← Windows launcher
├── run.sh                    ← Mac/Linux launcher
├── .env                      ← Config (secret key etc.)
│
├── backend/
│   └── modules/
│       ├── ml_analyzer.py    ← Stage 1: URL pattern ML
│       ├── nlp_analyzer.py   ← Stage 2: Page content NLP
│       ├── api_analyzer.py   ← Stage 3: VirusTotal + AbuseIPDB
│       └── score_normalizer.py ← Final score blending
│
├── models/                   ← Auto-generated ML model files
│   ├── ml_model.joblib       ← RandomForest (auto-created)
│   └── nlp_model.joblib      ← TF-IDF + LR (auto-created)
│
├── templates/
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
│
└── frontend/
    ├── css/
    │   ├── auth.css
    │   └── dashboard.css
    └── js/
        └── dashboard.js
```

---

## 🔑 API Keys (Optional but Recommended)

ThreatLens works WITHOUT API keys using ML + NLP only.  
To enable Stage 3 full threat intelligence:

1. Open the app → go to **SETTINGS** tab
2. Paste your keys:

| Service    | Free Tier | Get Key |
|------------|-----------|---------|
| VirusTotal | 4 req/min, 500/day | https://www.virustotal.com/gui/my-apikey |
| AbuseIPDB  | 1000 req/day | https://www.abuseipdb.com/account/api |

---

## 🧠 ML & NLP Models

### Stage 1 — ML (URL Features)
- **Algorithm**: RandomForestClassifier (150 trees, depth 12)
- **Features**: 19 URL-based features (length, entropy, TLD, keywords, etc.)
- **Based on**: UCI Phishing Websites Dataset + Kaggle Phishing URL Dataset
- **Reference**: Mohammad, Thabtah & McCluskey (2015) "Phishing Websites Features"
- **Model file**: Auto-generated on first run → `models/ml_model.joblib`

### Stage 2 — NLP (Page Content)
- **Algorithm**: TF-IDF Vectorizer + LogisticRegression
- **Features**: N-gram text patterns (1,2), urgency/credential lexicons
- **Based on**: PhishTank content analysis + DMOZ benign pages research
- **Model file**: Auto-generated on first run → `models/nlp_model.joblib`

---

## 🗃 Database

Uses **SQLite** — no installation needed, file stored as `threatlens.db`.

Tables:
- `user` — username, email, bcrypt-hashed password, created_at
- `search_history` — user_id, url, ml_score, nlp_score, api_score, final_score, verdict, timestamp

---

## 📊 Score Calculation

| Stage | Weight (with APIs) | Weight (no APIs) |
|-------|--------------------|-----------------|
| ML    | 30%                | 45%             |
| NLP   | 30%                | 45%             |
| API   | 40%                | 10%             |

**Verdict thresholds:**
- 0.00–0.20 → ✅ SAFE
- 0.20–0.40 → 🟡 LOW RISK  
- 0.40–0.60 → 🟠 SUSPICIOUS
- 0.60–0.80 → 🔴 HIGH RISK
- 0.80–1.00 → 💀 MALICIOUS

---

## 💻 Requirements

- Python 3.8+
- Internet connection (for NLP page fetch + API calls)
- No database server needed (SQLite built-in)
