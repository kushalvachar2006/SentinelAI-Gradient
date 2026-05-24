<div align="center">


# SentinelAI-Gradient

**AI-powered Security Operations Centre — from raw logs to actionable intelligence in seconds.**

[![License: MIT](https://img.shields.io/badge/License-MIT-orange.svg?style=flat-square)](LICENSE)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react)](https://react.dev)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Node.js](https://img.shields.io/badge/Node.js-Express-339933?style=flat-square&logo=node.js)](https://expressjs.com)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-47A248?style=flat-square&logo=mongodb)](https://mongodb.com)
[![Gemini](https://img.shields.io/badge/Gemini-2.5_Flash-4285F4?style=flat-square&logo=google)](https://deepmind.google/technologies/gemini)

[Live Demo](https://sentinelai-kva.netlify.app) · [Report Bug](https://github.com/kushalvachar2006/SentinelAI-Gradient/issues) · [Request Feature](https://github.com/kushalvachar2006/SentinelAI-Gradient/issues)

</div>

---

## What is SentinelAI-Gradient?

Security analysts spend hours triaging thousands of raw log lines every day — manually hunting for threats buried in noise. **SentinelAI-Gradient** replaces that grind with an end-to-end AI pipeline: upload a log file in any standard format, and within seconds you have a fully enriched, severity-scored, MITRE ATT&CK–tagged threat dashboard — with a conversational AI ready to answer questions about your data in plain English.

Built as a full-stack platform with a **dual-backend architecture** (Node.js + Python/FastAPI), it separates business logic from AI/ML concerns, making each tier independently scalable.

---

## Features

### 🔍 Multi-Format Log Ingestion
Upload log files up to 100 MB in any of five industry-standard formats. The Python service auto-detects structure and normalises every line into a consistent event model before passing it downstream.

| Format | Description |
|--------|-------------|
| **Syslog** | RFC 5424 system and network device logs |
| **AWS CloudTrail** | JSON event records from AWS audit trail |
| **Custom JSON** | Arbitrary JSON arrays or NDJSON streams |
| **CEF** | Common Event Format (ArcSight-compatible) |
| **LEEF** | Log Event Extended Format (IBM QRadar–compatible) |

### 🤖 AI-Powered Threat Detection
A two-stage detection engine runs on every ingested batch:

1. **Rule-based engine** — covers 20 threat types (SQL injection, ransomware C2, brute force, lateral movement, privilege escalation, DNS tunnelling, and more) with per-type base risk scores.
2. **IsolationForest ML filter** — trained at inference time on each batch to suppress false positives before any alert reaches the dashboard.

Every detected threat receives a **composite risk score (0–100)** and is mapped to a severity tier (Critical / High / Medium / Low / Info).

### 🌐 Real-Time Threat Enrichment
For every detected source IP, the enrichment pipeline queries three external intelligence sources concurrently (results are cached in-memory for 1 hour):

- **AbuseIPDB** — abuse confidence score, total community reports, ISP, last reported timestamp
- **VirusTotal** — malicious / suspicious / harmless / undetected engine counts + permalink
- **MaxMind GeoIP** — latitude, longitude, city, country, ASN, organisation, timezone

### 📊 SOC Dashboard
The live threat feed surfaces everything an analyst needs without leaving a single screen:

- Severity-filtered threat table (All / Critical / High / Medium / Low) sorted by risk score
- Per-alert **SlideOver panel** — MITRE ATT&CK technique and tactic, enrichment data, full AI explanation, raw log evidence
- Real-time UTC clock and optimistic dismiss/resolve actions backed by the REST API
- WebSocket-ready infrastructure (Socket.io) for push updates

### 📈 Analytics
Pre-aggregated KPIs and interactive Recharts visualisations pulled from the `/api/analytics` endpoint:

- Mean Time to Detect (MTTD)
- True Positive Rate (derived from status breakdown)
- Open Critical count and Average / Maximum risk score
- Threat timeline area chart (daily totals + critical breakdown)
- Threat-type bar chart with average risk per category

### 💬 SOC Chatbot (Gemini RAG)
A conversational interface that queries your **live MongoDB threat data** — not static documents. Ask anything:

> *"Which IPs are repeat offenders this week?"*  
> *"List all MITRE T1190 matches"*  
> *"Summarise critical alerts from the last 24 hours"*

The chat route uses a **model cascade** across three Gemini variants (gemini-2.5-flash → gemini-1.5-flash → gemini-2.5-pro) to maximise free-tier availability. If the Python AI service is unreachable, the Node layer falls back to its own Gemini SDK integration automatically.

### 🛡️ Autonomous Response Agent *(human-in-the-loop)*
For threats with a risk score above 85, the system can invoke a LangChain ReAct agent with three tools — `block_ip`, `draft_firewall_rule`, `create_ticket` — but **only after explicit analyst approval**. Every step of the agent's reasoning chain is stored as an audit trail.

### 📄 One-Click Incident Reports
The Python service generates board-ready PDF incident reports via WeasyPrint, including event timeline, indicators of compromise, MITRE mapping, and remediation steps.

---

## Architecture

```
Browser (React + Vite · port 5173)
        │
        │  REST  +  WebSocket (Socket.io)
        ▼
┌─────────────────────────────────────────┐
│  Node.js / Express  (port 3001)         │
│                                         │
│  /api/auth      JWT authentication      │
│  /api/logs      Log ingest + queue      │
│  /api/threats   CRUD + actions          │
│  /api/analytics MongoDB aggregations    │
│  /api/chat      Gemini RAG chatbot      │
│  /api/reports   PDF generation trigger  │
│  /api/approve   Autonomous agent gate   │
│                                         │
│  MongoDB Atlas ◄──────────────────────  │
│  Socket.io (real-time push)             │
└──────────────┬──────────────────────────┘
               │  Internal HTTP
               ▼
┌─────────────────────────────────────────┐
│  Python / FastAPI  (port 8000)          │
│                                         │
│  Log Parser        format detection     │
│  Threat Detection  rules + ML           │
│  Enrichment        AbuseIPDB / VT / Geo │
│  Gemini Agent      explain / chat / RAG │
│  Autonomous Agent  LangChain ReAct      │
│  Report Generator  WeasyPrint PDF       │
└─────────────────────────────────────────┘
```

The Node layer owns authentication, WebSocket push, and all client-facing APIs. The Python layer owns every AI/ML operation — it is stateless and can be scaled horizontally without affecting the Node service.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 18, Vite 5, React Router 7, Framer Motion, Recharts, React Flow, TanStack Query, Lucide React |
| **Styling** | Custom CSS design system — dark theme, CSS custom properties, glassmorphism |
| **State** | Zustand |
| **Node API** | Express 4, Mongoose 7, Socket.io 4, Multer, Helmet, Morgan, Winston |
| **Python API** | FastAPI 0.104, Uvicorn, Pydantic v2, Motor (async MongoDB), structlog |
| **AI / ML** | Google Gemini 2.5 Flash (chat + explanations), LangChain ReAct (autonomous agent), scikit-learn IsolationForest, NumPy, Pandas |
| **Enrichment** | AbuseIPDB API, VirusTotal API, MaxMind GeoLite2 |
| **PDF** | WeasyPrint |
| **Database** | MongoDB Atlas |
| **Deployment** | Netlify (frontend), Render (Python service) |

---

## Getting Started

### Prerequisites

- **Node.js** ≥ 18
- **Python** ≥ 3.11
- **MongoDB** — local instance or [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) free tier
- API keys: **Gemini** (required for AI features), **AbuseIPDB** and **VirusTotal** (optional, enrichment degrades gracefully without them)

### 1 · Clone

```bash
git clone https://github.com/kushalvachar2006/SentinelAI-Gradient.git
cd SentinelAI-Gradient
```

### 2 · Configure environment

**Node backend** — create `backend/.env`:

```env
PORT=3001
MONGODB_URI=mongodb+srv://<user>:<pass>@cluster.mongodb.net/sentinelai
JWT_SECRET=your_jwt_secret_here
GEMINI_API_KEY=your_gemini_api_key
PYTHON_SERVICE_URL=http://localhost:8000
DEMO_MODE=true
FRONTEND_URL=http://localhost:5173
```

**Python backend** — create `backend/app/.env`:

```env
PORT=8000
MONGODB_URI=mongodb+srv://<user>:<pass>@cluster.mongodb.net/sentinelai
GEMINI_API_KEY=your_gemini_api_key
ABUSEIPDB_KEY=your_abuseipdb_key          # optional
VIRUSTOTAL_KEY=your_virustotal_key         # optional
MAXMIND_DB_PATH=/opt/maxmind/GeoLite2-City.mmdb  # optional
JWT_SECRET=your_jwt_secret_here
NODE_SERVICE_URL=http://localhost:3001
```

**Frontend** — create `frontend/.env`:

```env
VITE_API_URL=http://localhost:3001
```

### 3 · Start everything

**Option A — one command (recommended)**

```bash
cd backend
npm install
bash start.sh
```

The startup script handles Node.js dependencies, creates a Python virtual environment, installs Python packages, and launches both services.

**Option B — manual (two terminals)**

```bash
# Terminal 1 — Node API
cd backend
npm install
npm run dev          # nodemon, hot-reload

# Terminal 2 — Python AI service
cd backend/app
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python main.py
```

### 4 · Start the frontend

```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173).

---

## API Reference

All protected routes require `Authorization: Bearer <token>`.  
In `DEMO_MODE=true`, the token `demo-token` is accepted without registration.

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/api/auth/login` | Authenticate, receive JWT |
| `POST` | `/api/logs/ingest` | Upload log file (multipart/form-data) |
| `GET` | `/api/threats` | Paginated threat list with filters |
| `POST` | `/api/threats/:id/action` | Analyst action (dismiss, resolve, assign…) |
| `DELETE`| `/api/threats/clear-all` | Remove all threats (dev/demo) |
| `GET` | `/api/analytics` | Pre-aggregated KPIs and chart data |
| `POST` | `/api/chat` | Gemini RAG chat query |
| `POST` | `/api/reports/:id` | Generate PDF incident report |
| `POST` | `/api/approve/:id` | Approve autonomous agent action |

Python service endpoints (internal, port 8000):

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/parse` | Parse raw log lines into normalised events |
| `POST` | `/detect` | Run threat detection + ML filter |
| `POST` | `/enrich` | IP enrichment (AbuseIPDB + VT + GeoIP) |
| `POST` | `/agent/explain` | Structured Gemini alert explanation |
| `POST` | `/agent/chat` | RAG chat over stored alerts |
| `POST` | `/agent/report` | Generate WeasyPrint PDF |
| `POST` | `/agent/predict` | Attack-window prediction |
| `GET` | `/health` | Service health check |

---

## Project Structure

```
SentinelAI-Gradient/
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── LandingPage.jsx     # Hero + feature overview
│   │   │   ├── Ingest.jsx          # Log upload UI + live preview
│   │   │   ├── Dashboard.jsx       # Main threat feed + SlideOver
│   │   │   ├── Analytics.jsx       # KPIs + Recharts visualisations
│   │   │   ├── Chat.jsx            # SOC chatbot (Gemini RAG)
│   │   │   └── ThreatDetail.jsx    # Full-page threat deep-dive
│   │   ├── components/
│   │   │   ├── dashboard/SlideOver.jsx
│   │   │   ├── layout/Navbar.jsx
│   │   │   └── ui/SeverityBadge.jsx
│   │   ├── store/useStore.js       # Zustand global state
│   │   └── data/mockData.js        # Demo/fallback data
│   └── vite.config.js              # Proxy → localhost:3001
│
└── backend/
    ├── index.js                    # Express entry point + Socket.io
    ├── routes/                     # auth · logs · threats · analytics · chat · reports · approve
    ├── models/                     # Mongoose schemas (Threat, Incident, User)
    ├── services/
    │   ├── queueService.js         # Async log processing queue
    │   └── socketService.js        # WebSocket event handlers
    ├── middleware/                  # auth · rateLimiter · errorHandler
    ├── start.sh                    # Unified startup script
    └── app/                        # Python FastAPI service
        ├── main.py                 # FastAPI entry point
        ├── modules/
        │   ├── log_parser.py       # Multi-format log normalisation
        │   └── threat_detection.py # Rule engine + IsolationForest
        ├── enrichment/
        │   └── enrichment.py       # AbuseIPDB · VirusTotal · MaxMind
        ├── agents/
        │   ├── gemini_agent.py     # Explain · Chat · Report · Predict
        │   └── autonomous_agent.py # LangChain ReAct agent
        └── config/
            ├── database.py         # Motor async MongoDB client
            └── settings.py         # Pydantic settings (env-driven)
```

---

## Roadmap

- [ ] WebSocket live-streaming of ingest progress (infrastructure in place)
- [ ] SIEM integrations — Splunk, Elastic, Microsoft Sentinel
- [ ] Role-based access control (analyst / manager / admin)
- [ ] Multi-tenant SOC support
- [ ] Jira / PagerDuty ticket creation from autonomous agent
- [ ] Threat intelligence feed ingestion (STIX / TAXII)
- [ ] Live network topology visualisation
- [ ] Exportable PDF summary reports (WeasyPrint pipeline built)

---

## Contributing

Contributions are welcome.

```bash
# Fork the repo, then:
git checkout -b feature/your-feature
git commit -m "feat: describe your change"
git push origin feature/your-feature
# Open a Pull Request
```

Please keep PRs focused — one feature or fix per PR makes review faster.

---

## License

MIT © [Kushal V Achar](https://github.com/kushalvachar2006)

---

<div align="center">

Built with ❤️ for Cybersecurity & AI Innovation

</div>