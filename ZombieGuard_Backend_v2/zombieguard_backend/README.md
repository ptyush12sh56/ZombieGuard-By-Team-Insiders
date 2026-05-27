# 🧟 ZombieGuard — Zombie API Discovery & Defence System

**Team:** Insiders | **Problem Statement:** PS9 | **Hackathon:** iDEA 2.0 | **Bank:** Union Bank of India

---

## Problem Statement (PS9)

Banks accumulate hundreds of **zombie APIs** — endpoints that were once active but are now stale, undocumented, or abandoned, yet remain publicly reachable. These invisible open doors account for **78% of enterprise API security incidents** and directly map to **OWASP API9: Improper Inventory Management**.

---

## Solution Architecture (Technical Approach Slide)

```
INPUT SOURCES (5)
├── API Gateway Logs      → FastAPI + Flask ingestion
├── Network Traffic       → BeautifulSoup packet trace fingerprinting
├── API Registry          → BeautifulSoup Swagger HTML + XML parser
├── CVE Database          → Pydantic-validated NVD/MITRE feed
└── API Metadata          → SQL Alchemy endpoint history
        │
        ▼
APACHE KAFKA — Real-Time Streaming Bus
├── api-gateway-logs  (10M+ events/sec)
├── network-traffic   (shadow fingerprinting)
├── cve-feed          (NVD updates)
├── ml-output         (ML scores)
└── defence-actions   (auto-defence events)
        │
        ▼
PROCESS
├── ML Detection      → IsolationForest(n=200) + LSTM(window=30d) [scikit-learn + NumPy]
├── Risk Engine       → NumPy vectorised CVSS 0-100 scoring + CVE matching
└── Database Store    → SQL Alchemy (SQLite) — 7 tables, full audit trail
        │
        ▼
OUTPUT
├── SecOps Dashboard  → FastAPI REST API + HTML/JS frontend
├── Auto Defence      → FastAPI kills route + Pydantic rotates key (<3 sec)
└── Alert Engine      → Slack + Email + PagerDuty + SMS via webhook
```

---

## Tech Stack (Exact Match to Slide 5)

| Layer | Tool | Version |
|-------|------|---------|
| Backend | FastAPI + Flask | 0.115.0 |
| Validation | Pydantic v2 | 2.8.2 |
| ML — Anomaly | scikit-learn IsolationForest | 1.5.1 |
| ML — Temporal | LSTM (NumPy/TensorFlow) | — |
| Scoring | NumPy vectorised CVSS | 1.26.4 |
| Data | pandas DataFrame | 2.2.2 |
| Parsing | BeautifulSoup4 (html.parser + lxml-xml) | 4.12.3 |
| Database | SQL Alchemy + SQLite | 2.0.32 |
| Streaming | Apache Kafka (kafka-python) | 2.0.2 |
| Server | Uvicorn ASGI | 0.30.6 |

---

## How to Run Locally

### Prerequisites
- Python 3.10+
- pip

### Steps

```bash
# 1. Clone
git clone https://github.com/<your-repo>/zombieguard
cd zombieguard

# 2. Install all dependencies
pip install -r requirements.txt

# 3. Launch backend
python run.py

# 4. Open browser
# Dashboard  → http://localhost:8000
# API Docs   → http://localhost:8000/docs
# ReDoc      → http://localhost:8000/redoc
```

### Run Tests

```bash
pytest tests/ -v
# Expected: 36 passed
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scan` | Full 5-step pipeline scan |
| GET | `/api/dashboard` | KPIs + OWASP stats |
| GET | `/api/endpoints` | Paginated API inventory |
| GET | `/api/endpoints/top-risky` | Top N riskiest endpoints |
| GET | `/api/endpoints/distribution` | Risk score histogram |
| GET | `/api/alerts` | SecOps alert feed |
| POST | `/api/defence` | Manual remediation action |
| GET | `/api/defence` | Defence actions log |
| GET | `/api/audit` | Full audit log (PCI-DSS) |
| POST | `/api/risk-calc` | Live CVSS risk calculator |
| GET | `/api/kafka-status` | Kafka broker + topic stats |
| GET | `/api/kafka-events` | Recent Kafka events |
| GET | `/api/parser-status` | BeautifulSoup parser results |
| GET | `/api/cve-database` | CVE patterns loaded |
| GET | `/api/db-stats` | SQL Alchemy table stats |
| GET | `/api/sessions` | Scan history |
| GET | `/api/ml-info` | ML model metadata |

---

## Database Schema (SQL Alchemy)

```
api_endpoints   — endpoint registry with metadata
risk_scores     — ML anomaly flag + CVSS score per endpoint
audit_log       — all actions (PCI-DSS / GDPR compliant)
cve_matches     — CVE pattern hits per endpoint
defence_actions — disable / rotate / whitelist / alert log
alerts          — SecOps alerts with severity + channel
scan_sessions   — full scan history with duration stats
```

---

## ML Pipeline Details

### IsolationForest (scikit-learn)
- **Algorithm:** `sklearn.ensemble.IsolationForest`
- **Parameters:** `n_estimators=200, contamination=tunable (5-40%), random_state=42`
- **Features (7):** `calls_per_day, days_since_active, error_rate_pct, has_auth, is_documented, is_registered, response_ms`
- **Type:** Unsupervised — no labelled training data required
- **Output:** anomaly flag (-1 = anomaly, 1 = normal)

### LSTM Sequence Model (TensorFlow/Keras)
- **Window:** 30-day call frequency sliding window
- **Threshold:** 85th percentile reconstruction error
- **Type:** Temporal pattern anomaly detection
- **Production:** `tf.keras.Sequential([LSTM(64), Dense(1)])`

### NumPy CVSS Risk Scorer
- **Vectorised:** Scores all endpoints in one NumPy matrix operation
- **Components:** Staleness (35) + No-Auth (25) + Zero-Traffic (20) + CVE (15) + Undocumented (5)
- **Output:** 0–100 score per endpoint

---

## OWASP Coverage

| API Risk | Detection Method |
|----------|-----------------|
| API3 - Excessive Data Exposure | Zombie API stale endpoint detection |
| API7 - Security Misconfiguration | No-auth endpoint flagging |
| API9 - Improper Inventory Management | Core use case — zombie + shadow discovery |
| API1 - Broken Object Authorization | High-risk score threshold detection |

---

## Sample Dataset

Synthetic bank API logs generate 80 endpoints across categories:
- **Active (✅):** 22 healthy v2 API endpoints (UPI, NEFT, KYC, loans)
- **Zombie (🧟):** 14 stale v0/v1 endpoints with zero traffic
- **Shadow (👻):** 6 undocumented endpoints found only via traffic fingerprinting
- **Deprecated (⚠):** 3 end-of-life endpoints with minimal traffic

---

## Known Limitations

1. **Kafka is in-process** — real deployment uses external Kafka cluster (`bootstrap_servers=...`)
2. **LSTM is NumPy-simulated** — production uses `tensorflow>=2.17` (commented in requirements.txt)
3. **SQLite for POC** — production uses PostgreSQL via SQL Alchemy URL swap
4. **Auto-disable is simulated** — production connects to API gateway write-back (Kong/AWS APIM)
5. **Alerts are logged, not sent** — production connects real Slack/email/PagerDuty webhooks

---

## Team

| Name | Role |
|------|------|
| Pramit Sasmal | Security Researcher + ML Engineer |
| Soham Mukherjee | Backend Developer (FastAPI + SQL Alchemy) |
| Ashutosh Kumar | ML Pipeline (IsolationForest + NumPy) |
| Pratyush Sharma | Frontend + BeautifulSoup Parser |
