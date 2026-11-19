# VAPTProX 🛡️
### Professional Full-Stack Vulnerability Assessment & Penetration Testing Suite

**VAPTProX** is a unified, enterprise-grade full-stack security scanning platform built by synthesizing the capabilities of three premier open-source penetration testing and vulnerability auditing projects:
1. **[VulnScanner](https://github.com/shawnsaju/VulnScanner)**: Fast multi-threaded port scanner, modern cyber dark glassmorphism dashboard, dynamic scanning stages, and ReportLab PDF reporting engine.
2. **[SecureScope-AI](https://github.com/BasharAlsabal/SecureScope-AI)**: Deep passive reconnaissance, HTTP security headers analyzer, SSL/TLS handshake & ciphers evaluation, DNS/WHOIS records analysis, web technology fingerprinting, rule-based & LLM AI vulnerability analysis, and JWT-authenticated SQLite database history.
3. **[webvapt](https://github.com/Neecool/webvapt)**: Active crawling engine, lab-based SQL Injection (error/boolean-blind), Reflected/Stored XSS, CSRF token absence detection, IDOR (Insecure Direct Object Reference) checks, and an intentionally vulnerable testbed application (`VulnLab`).

---

## 📸 Feature Matrix

| Module | Features & Capabilities |
|---|---|
| **Authentication** | User Registration, Login, bcrypt password hashing, JWT Bearer tokens |
| **Dashboard** | Dynamic security score (0-100), scan history table, severity counters, quick scan targets |
| **Reconnaissance** | Comprehensive DNS records (A, AAAA, MX, NS, TXT, CNAME), WHOIS registrar/domain information, and web technology/server stack detection |
| **Port Scanner** | High-speed concurrent TCP port scanner detecting exposed common services (SSH, FTP, HTTP, HTTPS, MySQL, Postgres, RDP, etc.) |
| **SQL Injection** | Automated heuristic and payload injection tests in authorized lab environments detecting SQL syntax errors and boolean differences |
| **XSS Scanner** | Detects Reflected and Stored Cross-Site Scripting via contextual script injections and DOM attribute reflections |
| **CSRF Analysis** | Evaluates sensitive forms (POST/PUT/DELETE) for anti-CSRF token protection and SameSite cookie defenses |
| **SSL/TLS Analysis** | SSL certificate validation, issuer, expiration, days remaining, cipher support, and letter-grade scoring (A+, A, B, F) |
| **Security Headers** | Detailed audit of `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy` |
| **Cookie Analysis** | Analyzes session cookies for `HttpOnly`, `Secure`, and `SameSite` compliance |
| **Risk Analysis** | Automatic categorization of all findings into Critical, High, Medium, Low, and Info tiers with severity-weighted scoring |
| **PDF Reporting** | Instant downloadable PDF security reports summarizing executive score, vulnerability metrics, and remediation guidance |
| **AI Analyst** | Contextual vulnerability explainer providing root-cause analysis and actionable remediation advice for identified flaws |
| **VulnLab Testbed** | Built-in isolated Flask application containing deliberate OWASP Top 10 vulnerabilities for safe, authorized offline testing |

---

## 🏗️ Architecture

```
VAPTProX/
├── backend/
│   ├── app/
│   │   ├── api/             # FastAPI routers (auth, scan, lab_scan, history)
│   │   ├── core/            # Configuration, security utils (JWT, bcrypt)
│   │   ├── db/              # SQLAlchemy database setup & User/Scan models
│   │   ├── scanner/         # Active crawl & checks (sqli, xss, csrf, idor, auth)
│   │   ├── schemas/         # Pydantic v2 schemas for requests & responses
│   │   ├── services/        # Recon, headers, cookies, ports, ssl, score, AI, PDF
│   │   └── main.py          # FastAPI application entrypoint
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── api/             # Axios client & scanner API functions
│   │   ├── components/      # Navbar, ScoreCard, AIAnalyst, Download, Tabs
│   │   │   └── tabs/        # HeadersTab, CookiesTab, SSLTab, PortsTab, DNSTab, TechTab
│   │   ├── context/         # AuthContext (React Context API)
│   │   ├── pages/           # Home, Results, Dashboard, LabScanner, Login, Register
│   │   ├── App.jsx
│   │   ├── index.css        # Cybersecurity dark glassmorphic styling system
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
├── vulnlab/                 # Intentionally vulnerable practice application (Flask)
│   ├── templates/           # OWASP-vulnerable HTML templates
│   ├── app.py
│   └── requirements.txt
├── start.sh                 # Single-command startup script
└── README.md
```

---

## ⚡ Quick Start

### 1. Automated Start (Recommended)
From the `VAPTProX` root folder, run:
```bash
./start.sh
```
This automatically initializes Python virtual environments, installs requirements for backend and frontend, and boots up all services simultaneously:
- **Web Application UI:** [http://localhost:5173](http://localhost:5173)
- **FastAPI Interactive API Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **VulnLab Intentionally Vulnerable Target:** [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

### 2. Manual Startup

#### Backend (FastAPI)
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Frontend (React + Vite)
```bash
cd frontend
npm install
npm run dev
```

#### VulnLab (Practice Target)
```bash
cd vulnlab
pip install -r requirements.txt
python3 app.py
```

---

## 🛡️ Educational & Authorized Testing Notice

> [!CAUTION]
> **LEGAL NOTICE & ETHICAL DISCLAIMER**
> 
> VAPTProX is engineered exclusively for **authorized security audits, educational research, and lab-based vulnerability validation**.
> Testing targets without explicit prior written authorization from the system owner is strictly prohibited and violates national and international cyber crime laws (e.g., Computer Fraud and Abuse Act 18 U.S.C. § 1030).
> Always use the included **VulnLab** test environment (`http://127.0.0.1:5000`) or dedicated test ranges (e.g. `testphp.vulnweb.com`) for active testing.

