import os
import sys
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super(NumberedCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))
        
        # Header (on pages after the first)
        if self._pageNumber > 1:
            self.drawString(54, letter[1] - 36, "VAPTProX — Technical Project Report & Interview Guide")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, letter[1] - 42, letter[0] - 54, letter[1] - 42)
            
        # Footer
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(letter[0] - 54, 36, page_str)
        self.drawString(54, 36, "CONFIDENTIAL & PROPRIETARY — VAPTProX Security Engineering")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 48, letter[0] - 54, 48)
        self.restoreState()

def create_report_pdf(output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#3b82f6"),
        spaceAfter=15,
    )
    
    meta_style = ParagraphStyle(
        'DocMeta',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=20,
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=19,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=16,
        spaceAfter=8,
        keepWithNext=True,
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0369a1"),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#334155"),
        spaceAfter=6,
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4,
    )

    q_style = ParagraphStyle(
        'Question_Style',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True,
    )

    ans_style = ParagraphStyle(
        'Answer_Style',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13.5,
        textColor=colors.HexColor("#1e293b"),
        leftIndent=12,
        spaceAfter=10,
    )

    th_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white,
    )

    tb_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1e293b"),
    )

    tb_code = ParagraphStyle(
        'TableCellCode',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0f766e"),
    )

    story = []

    # Title & Header
    story.append(Paragraph("VAPTProX: Enterprise VAPT Suite", title_style))
    story.append(Paragraph("Comprehensive Technical Architecture, Features & Interview Guide", subtitle_style))
    story.append(Paragraph("<b>Version:</b> 2.0.0 &nbsp;|&nbsp; <b>Classification:</b> Confidential &nbsp;|&nbsp; <b>Date:</b> November 2026", meta_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#3b82f6"), spaceAfter=14))

    # 1. Executive Summary
    story.append(Paragraph("1. Executive Summary & Project Overview", h1_style))
    story.append(Paragraph(
        "<b>VAPTProX</b> is an automated full-stack vulnerability assessment and penetration testing platform. "
        "It was engineered by analyzing, extracting, and synthesizing core capabilities from three renowned open-source repositories: "
        "<b>VulnScanner</b> (multi-threaded socket port scanner, PDF reports, cybersecurity UI), "
        "<b>SecureScope-AI</b> (passive reconnaissance, security headers, SSL/TLS grading, tech fingerprinting, scoring models), and "
        "<b>webvapt</b> (active crawler, SQL injection, XSS, CSRF, IDOR checks, and the VulnLab practice target).",
        body_style
    ))
    story.append(Paragraph(
        "The system empowers security auditors and DevOps teams to execute unified perimeter audits and receive instant, "
        "real-time natural language vulnerability insights powered by high-speed Large Language Models (Groq / Gemini).",
        body_style
    ))

    # 2. Technology Stack Table
    story.append(Paragraph("2. Complete Technology Stack", h1_style))
    
    tech_data = [
        [Paragraph("Layer", th_style), Paragraph("Technology", th_style), Paragraph("Version", th_style), Paragraph("Purpose & Rationale", th_style)],
        [Paragraph("Frontend UI", tb_style), Paragraph("React", tb_style), Paragraph("18.3.1", tb_code), Paragraph("Reactive component architecture, virtual DOM state synchronization.", tb_style)],
        [Paragraph("Bundler", tb_style), Paragraph("Vite", tb_style), Paragraph("5.4.2", tb_code), Paragraph("Ultra-fast Hot Module Replacement (HMR) and optimized Rollup bundling.", tb_style)],
        [Paragraph("Styling", tb_style), Paragraph("Vanilla CSS3", tb_style), Paragraph("Custom", tb_code), Paragraph("Dark glassmorphism design system; 0 external CSS dependencies.", tb_style)],
        [Paragraph("Backend", tb_style), Paragraph("FastAPI", tb_style), Paragraph("0.111.0", tb_code), Paragraph("High-throughput ASGI async web framework with automatic OpenAPI docs.", tb_style)],
        [Paragraph("ASGI Server", tb_style), Paragraph("Uvicorn + uvloop", tb_style), Paragraph("0.29.0", tb_code), Paragraph("High-concurrency event-loop runner built on libuv.", tb_style)],
        [Paragraph("Data Schemas", tb_style), Paragraph("Pydantic v2", tb_style), Paragraph("2.7.1", tb_code), Paragraph("Type validation, payload serialization (model_dump()).", tb_style)],
        [Paragraph("HTTP Client", tb_style), Paragraph("HTTPX", tb_style), Paragraph("0.27.0", tb_code), Paragraph("Asynchronous HTTP requests supporting SSL contexts and redirects.", tb_style)],
        [Paragraph("PDF Engine", tb_style), Paragraph("ReportLab", tb_style), Paragraph("4.2.0", tb_code), Paragraph("Vector-based programmatic PDF audit generation.", tb_style)],
        [Paragraph("LLM Engine", tb_style), Paragraph("Groq (GPT-OSS-120B)", tb_style), Paragraph("Cloud API", tb_code), Paragraph("Real-time natural language security reasoning in under 1.5s.", tb_style)],
        [Paragraph("LLM Fallback", tb_style), Paragraph("Google Gemini", tb_style), Paragraph("v1beta", tb_code), Paragraph("Automated fallback for threat modeling & impact analysis.", tb_style)],
        [Paragraph("Database", tb_style), Paragraph("SQLAlchemy + SQLite", tb_style), Paragraph("2.0.30", tb_code), Paragraph("Lightweight ORM and local persistent scan history tracking.", tb_style)],
    ]
    
    t_tech = Table(tech_data, colWidths=[1.1*inch, 1.4*inch, 0.8*inch, 3.7*inch])
    t_tech.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
    ]))
    story.append(t_tech)
    story.append(Spacer(1, 10))

    # 3. Core Features Breakdown
    story.append(Paragraph("3. Core Features & Implementation Details", h1_style))

    story.append(Paragraph("3.1 High-Speed Concurrent Port Scanner", h2_style))
    story.append(Paragraph(
        "VAPTProX probes 20 high-value network service ports (SSH, HTTP, HTTPS, MySQL, RDP, Redis, MongoDB, etc.) "
        "using a concurrent <code>ThreadPoolExecutor</code> (20 workers) with socket connection timeouts capped at 0.8s. "
        "This architectural enhancement reduced total port scan time from <b>30 seconds down to ~0.8 seconds</b>.",
        body_style
    ))

    story.append(Paragraph("3.2 Passive Reconnaissance, DNS & WHOIS", h2_style))
    story.append(Paragraph(
        "Resolves A, AAAA, MX, NS, TXT, and CNAME records via <code>dnspython</code>, while evaluating SPF (Sender Policy Framework) "
        "and DMARC records to identify domain spoofing vulnerabilities. Deep WHOIS inspection queries regional registries for registrar, "
        "creation dates, expiration countdowns, and organizational details.",
        body_style
    ))

    story.append(Paragraph("3.3 HTTP Security Headers & Cookie Audit", h2_style))
    story.append(Paragraph(
        "Validates incoming server response headers against OWASP security baselines: <b>Content-Security-Policy</b> (XSS/injection defense), "
        "<b>Strict-Transport-Security</b> (protocol downgrade mitigation), <b>X-Frame-Options</b> (clickjacking defense), "
        "<b>X-Content-Type-Options</b> (MIME sniffing prevention), and CORS wildcard exposures. Cookies are evaluated for <code>HttpOnly</code>, "
        "<code>Secure</code>, and <code>SameSite</code> directives.",
        body_style
    ))

    story.append(Paragraph("3.4 SSL/TLS Certificate & Handshake Grading", h2_style))
    story.append(Paragraph(
        "Performs a raw TLS handshake to decode the X.509 certificate, verify issuing authority, calculate exact days until expiration, "
        "and check protocol versions (TLS 1.2/1.3 vs legacy SSLv3/TLS 1.0). Assigns standard security grades (<b>A+</b>, <b>A</b>, <b>B</b>, <b>F</b>).",
        body_style
    ))

    story.append(Paragraph("3.5 Multi-Category Security Scoring Algorithm", h2_style))
    story.append(Paragraph(
        "Normalizes findings into a single 0–100 score across 4 weighted categories: "
        "<b>Headers (30 pts)</b>, <b>Cookies (20 pts)</b>, <b>SSL/TLS (25 pts)</b>, and <b>Tech/Ports (25 pts)</b>. "
        "Standard deductions apply for vulnerabilities: Critical (-25), High (-15), Medium (-8), and Low (-4).",
        body_style
    ))

    story.append(Paragraph("3.6 Integrated Groq & Gemini LLM Analyst", h2_style))
    story.append(Paragraph(
        "Transmits normalized telemetry (active headers, missing defenses, TLS configuration, port mappings) directly to <b>Groq (GPT-OSS-120B)</b> "
        "with automated fallback to <b>Gemini</b>. The LLM produces four tailored sections: Executive Summary, Key Findings, Actionable Recommendations, and Business Impact.",
        body_style
    ))

    story.append(PageBreak())

    # 4. Technical Interview Preparation (Q&A)
    story.append(Paragraph("4. Technical Interview Preparation Guide (Q&A)", h1_style))
    story.append(Paragraph("Review these high-frequency interview questions tailored to the VAPTProX codebase and architecture.", meta_style))

    qa_list = [
        (
            "Q1: Can you give an elevator pitch for VAPTProX?",
            "VAPTProX is an automated full-stack vulnerability assessment and penetration testing suite. "
            "It takes any web target URL, concurrently audits its transport security, HTTP security headers, cookies, DNS records, open ports, "
            "and technology stack, calculates a weighted security score, and leverages an LLM (Groq / Gemini) to generate tailored penetration "
            "test reports with actionable remediation steps and downloadable PDF audits."
        ),
        (
            "Q2: How did you approach unifying three separate open-source repositories?",
            "I decomposed each repository by core competency: VulnScanner provided the multi-threaded socket port scanner, PDF compilation, and UI styles; "
            "SecureScope-AI contributed passive reconnaissance (headers, SSL validation, DNS/WHOIS, tech fingerprinting) and scoring algorithms; "
            "and webvapt provided crawling logic, active OWASP checks, and the VulnLab practice target. "
            "I consolidated these into a unified FastAPI backend with Pydantic v2 schemas and a modern React 18 frontend."
        ),
        (
            "Q3: Why are HSTS and CSP critical for modern web applications?",
            "HSTS (Strict-Transport-Security) forces browsers to strictly communicate over HTTPS, preventing SSL-stripping and man-in-the-middle attacks. "
            "CSP (Content-Security-Policy) restricts authorized sources for script, style, and object execution, acting as the primary defense-in-depth "
            "barrier against Cross-Site Scripting (XSS) and data exfiltration."
        ),
        (
            "Q4: Explain how VAPTProX audits cookie security flags.",
            "VAPTProX inspects Set-Cookie headers for three defensive flags: "
            "(1) 'Secure' ensures transmission strictly over encrypted TLS connections. "
            "(2) 'HttpOnly' prevents client-side JavaScript access via document.cookie, mitigating session hijacking during XSS attacks. "
            "(3) 'SameSite' (Lax/Strict) prevents browsers from sending cookies with cross-site requests, mitigating Cross-Site Request Forgery (CSRF)."
        ),
        (
            "Q5: How did you optimize the port scanner from 30 seconds to under 1 second?",
            "The initial port scanner probed 20 ports sequentially with a 1.5-second socket timeout, meaning closed or filtered ports caused cumulative delays of 30+ seconds. "
            "I re-engineered the scanner using Python's concurrent.futures.ThreadPoolExecutor with 20 worker threads and a 0.8s timeout. "
            "All 20 ports are probed concurrently, slashing total execution time to under 800 milliseconds."
        ),
        (
            "Q6: How did you prevent synchronous socket calls from blocking FastAPI's async event loop?",
            "FastAPI runs on an asynchronous event loop (uvloop). Blocking calls like socket.create_connection, dns.resolver, and SSL handshakes would stall the loop. "
            "I offloaded synchronous blocking methods into background thread pools using asyncio.to_thread(), and joined all concurrent audit tasks using asyncio.gather()."
        ),
        (
            "Q7: Describe a major frontend bug you diagnosed and fixed during development.",
            "During testing, the UI was freezing on 'Checking cookies...'. By analyzing Chrome DevTools, I confirmed the backend had returned HTTP 200 in 31ms. "
            "The bug was in Results.jsx: it attempted [ ...(data.cookies || []) ], but data.cookies was an object ({ target_url, findings: [] }). "
            "Spreading an object into an array threw 'TypeError: data.cookies is not iterable', crashing component mounting while the progress bar displayed a hardcoded pulsing state. "
            "I resolved this by safely unpacking data.cookies?.findings and making the progress bar 100% dynamic."
        ),
        (
            "Q8: What was the cause behind identical scan results on different websites, and how was it solved?",
            "The backend server was initially executed within an isolated terminal sandbox proxy. The sandbox blocked all outbound socket calls (socket.create_connection) "
            "with 'Operation not permitted' and intercepted HTTP requests with a generic 403 Forbidden page containing 0 headers. "
            "Because every target received the identical proxy error, all websites scored an identical 45. "
            "Restarting the backend server with elevated network access enabled real live outbound network connections, immediately producing distinct results."
        ),
        (
            "Q9: What serialization issue occurred with Pydantic v2 and LLM payloads?",
            "In Pydantic v2, models cannot be directly serialized by standard json.dumps()—calling getattr(h, '__dict__', h) returns the Pydantic instance rather than a dict, "
            "throwing 'TypeError: Object of type HeaderFinding is not JSON serializable'. "
            "I built a recursive _serialize_item() utility that invokes .model_dump() on Pydantic instances and converts nested structures into clean JSON-compliant dicts."
        ),
        (
            "Q10: How did you integrate Groq and Gemini to avoid generic or hallucinated responses?",
            "I fed normalized, verified telemetry (exact detected frameworks, active headers, certificate days remaining, open ports) directly into the LLM system prompt. "
            "By enforcing response_format: {'type': 'json_object'} on Groq's openai/gpt-oss-120b model, the LLM generates deeply contextual, site-specific executive narratives "
            "and prioritized technical remediation steps in under 1.5 seconds."
        ),
        (
            "Q11: How would you scale VAPTProX for enterprise-level multi-target scanning?",
            "I would introduce a distributed task queue (Celery or ARQ with Redis/RabbitMQ) to decouple HTTP scan initiation from execution. "
            "Scanning workers would run as containerized microservices in Kubernetes, streaming real-time scan events back to the React client via WebSockets."
        )
    ]

    for q, a in qa_list:
        story.append(Paragraph(q, q_style))
        story.append(Paragraph(f"<b>Answer:</b> {a}", ans_style))
        story.append(Spacer(1, 4))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"PDF generated successfully at {output_path}")

if __name__ == "__main__":
    out_dir = "/Users/nirmalyapradhan/Downloads/VAPT/VAPTProX"
    out_file = os.path.join(out_dir, "VAPTProX_Project_Report_and_Interview_Guide.pdf")
    create_report_pdf(out_file)

