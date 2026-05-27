# 🧟 ZombieGuard Frontend
**React + Vite + Framer Motion Dashboard**  
**iDEA 2.0 Hackathon | PS9 | Team Insiders | Union Bank of India**

---

## Design System (VaultShield Template Pattern)

| Property | Value |
|----------|-------|
| Display font | `Bebas Neue` — impact headings, KPI numbers |
| Mono font | `IBM Plex Mono` — labels, code, timestamps |
| Body font | `Instrument Sans` — body text, nav |
| Primary accent | `#e8242c` (red) — critical alerts, CTA |
| Secondary accent | `#00d4a8` (teal) — active, healthy |
| Background | `#050a0f` + grid overlay |
| Grid pattern | `60px × 60px` with `1px` lines at 35% opacity |

---

## Option A — Standalone HTML (No Build Needed)

Open `zombieguard_standalone.html` directly in your browser.  
It uses Babel in-browser to compile JSX. Works without Node.js.

> **Note:** The standalone version calls the FastAPI backend at `http://localhost:8000`.  
> Start the backend first: `cd ../zombieguard_backend && python run.py`

---

## Option B — Vite Dev Server (Full React, Recommended)

```bash
# 1. Install
npm install

# 2. Start backend (separate terminal)
cd ../zombieguard_backend && python run.py

# 3. Start frontend dev server (proxies /api/* to :8000)
npm run dev

# 4. Open http://localhost:3000
```

---

## Option C — Integrated (Served by FastAPI)

The FastAPI backend at `zombieguard_backend/templates/index.html` serves the full dashboard at `http://localhost:8000`. No separate frontend server needed.

```bash
cd zombieguard_backend
python run.py
# Dashboard → http://localhost:8000
```

---

## Pages & Features

| Page | Route | Description |
|------|-------|-------------|
| Dashboard | `/` | KPI grid, charts, OWASP violations, live ticker |
| Run Scan | `/scan` | 5-step pipeline with animated progress + live log |
| Input Sources | `/input` | BeautifulSoup parser status from `/api/parser-status` |
| Kafka Stream | `/kafka` | Real-time topic throughput + event log |
| ML Detection | `/mldetect` | IsolationForest + LSTM metrics + feature importances |
| Risk Engine | `/riskengine` | CVSS scoring breakdown + live calculator |
| Database Store | `/dbstore` | SQL Alchemy schema + audit log + DB stats |
| API Inventory | `/inventory` | Full paginated table with filter/search/kill |
| Auto Defence | `/defence` | Defence flow diagram + log + manual remediation |
| Alert Engine | `/alertengine` | SecOps feed: Slack/Email/PagerDuty |
| OWASP Coverage | `/owasp` | API1/API3/API7/API9 violations live |
| Impact & Benefits | `/impact` | Slide 7 — before/after table, ROI metrics |
| vs Competitors | `/compare` | Slide 4 — competitor table + business model |
| Risk Calculator | `/calculator` | Interactive POST /api/risk-calc with breakdown |
| Scan History | `/sessions` | SQL Alchemy scan sessions table |

---

## API Integration

All pages call the FastAPI backend via `fetch()`:

| Frontend Call | Backend Endpoint |
|--------------|-----------------|
| Dashboard KPIs | `GET /api/dashboard` |
| Run scan | `POST /api/scan` |
| Inventory | `GET /api/endpoints?page=1&classification=ZOMBIE` |
| Top risky | `GET /api/endpoints/top-risky?n=8` |
| Distribution | `GET /api/endpoints/distribution` |
| Alerts | `GET /api/alerts` |
| Defence log | `GET /api/defence` |
| Manual action | `POST /api/defence` |
| Audit log | `GET /api/audit` |
| Risk calculator | `POST /api/risk-calc` |
| Kafka status | `GET /api/kafka-status` |
| Kafka events | `GET /api/kafka-events` |
| Parser status | `GET /api/parser-status` |
| CVE database | `GET /api/cve-database` |
| DB stats | `GET /api/db-stats` |
| Scan history | `GET /api/sessions` |
| ML info | `GET /api/ml-info` |

---

## File Structure

```
zombieguard_frontend/
├── index.html                  # Vite entry point
├── package.json
├── vite.config.js              # Proxies /api/* → localhost:8000
├── tailwind.config.js
├── postcss.config.js
├── zombieguard_standalone.html # ← Open this for instant demo (no build)
├── src/
│   ├── main.jsx                # React root mount
│   ├── App.jsx                 # All pages & components (~1500 lines)
│   └── index.css               # Global CSS + design tokens + animations
└── README.md
```
