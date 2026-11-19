import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable,
)

SEVERITY_COLORS = {
    "Critical": "#7A0C0C", "High": "#C0392B",
    "Medium": "#E08E0B", "Low": "#2E7D32", "Info": "#2C6FBB",
}


def _esc(text):
    if text is None:
        return ""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _hex(h):
    return colors.HexColor(h)


def _get_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("VTitle", fontSize=26, leading=32, spaceAfter=6, textColor=_hex("#111111"), fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle("VSubtitle", fontSize=12, textColor=_hex("#555555"), spaceAfter=20))
    styles.add(ParagraphStyle("VSectionHead", fontSize=14, spaceBefore=18, spaceAfter=8, textColor=_hex("#111111"), fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle("VLabel", fontSize=9, textColor=_hex("#777777"), spaceBefore=5, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle("VBody", fontSize=10, leading=14, textColor=_hex("#222222")))
    styles.add(ParagraphStyle("VEvidence", fontSize=8.5, leading=12, fontName="Courier", textColor=_hex("#333333"), backColor=_hex("#f4f4f4")))
    styles.add(ParagraphStyle("VDisclaimer", fontSize=8, textColor=_hex("#999999")))
    return styles


def _table(rows, col_widths, header_bg="#111111"):
    t = Table(rows, colWidths=col_widths)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _hex(header_bg)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, _hex("#eeeeee")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    t.setStyle(TableStyle(style))
    return t


def generate_pdf_report(scan_data: dict, filename: str) -> str:
    os.makedirs(os.path.dirname(filename) if os.path.dirname(filename) else ".", exist_ok=True)
    doc = SimpleDocTemplate(filename, pagesize=A4,
        topMargin=22*mm, bottomMargin=18*mm, leftMargin=18*mm, rightMargin=18*mm)
    styles = _get_styles()
    story = []
    now = datetime.now().strftime("%d %B %Y, %H:%M")
    target = scan_data.get("target_url", "Unknown")
    score_data = scan_data.get("security_score", {})
    score = score_data.get("score", 0)
    risk_level = score_data.get("risk_level", "Unknown")
    ai = scan_data.get("ai_analysis", {})

    # ── Cover ─────────────────────────────────────────────
    story.append(Spacer(1, 10))
    story.append(Paragraph("🛡 VAPTProX", styles["VTitle"]))
    story.append(Paragraph("Web Application Vulnerability Assessment Report", styles["VSubtitle"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=_hex("#333333")))
    story.append(Spacer(1, 16))

    meta = Table([
        ["Target URL", _esc(target)],
        ["Scan Date", now],
        ["Security Score", f"{score}/100"],
        ["Risk Level", risk_level],
        ["Report Type", "Full VAPT Scan (Recon + Passive + Active Analysis)"],
    ], colWidths=[120, 350])
    meta.setStyle(TableStyle([
        ("FONTSIZE", (0,0),(-1,-1), 10),
        ("TEXTCOLOR", (0,0),(0,-1), _hex("#555555")),
        ("FONTNAME", (0,0),(0,-1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0,0),(-1,-1), 7),
        ("TOPPADDING", (0,0),(-1,-1), 7),
        ("LINEBELOW", (0,0),(-1,-1), 0.5, _hex("#eeeeee")),
    ]))
    story.append(meta)
    story.append(Spacer(1, 20))

    # ── Score breakdown ───────────────────────────────────
    story.append(Paragraph("Security Score Breakdown", styles["VSectionHead"]))
    cats = score_data.get("categories", [])
    if cats:
        rows = [["Category", "Score", "Max", "Grade"]]
        for cat in cats:
            cs = cat.get("score", 0); cm = cat.get("max_score", 0)
            pct = round((cs/cm)*100) if cm else 0
            grade = "✅ Good" if pct >= 70 else ("⚠️ Moderate" if pct >= 40 else "❌ Poor")
            rows.append([cat.get("category",""), str(cs), str(cm), grade])
        story.append(_table(rows, [220, 60, 60, 80]))
    story.append(Spacer(1, 16))
    story.append(PageBreak())

    # ── AI Executive Summary ──────────────────────────────
    story.append(Paragraph("Executive Summary (AI Analysis)", styles["VSectionHead"]))
    story.append(Paragraph(_esc(ai.get("executive_summary", "")), styles["VBody"]))
    story.append(Spacer(1, 10))

    if ai.get("key_findings"):
        story.append(Paragraph("Key Findings", styles["VLabel"]))
        for f in ai.get("key_findings", []):
            story.append(Paragraph(f"• {_esc(f)}", styles["VBody"]))
    story.append(Spacer(1, 10))

    if ai.get("priority_recommendations"):
        story.append(Paragraph("Priority Recommendations", styles["VLabel"]))
        for r in ai.get("priority_recommendations", []):
            story.append(Paragraph(f"• {_esc(r)}", styles["VBody"]))
    story.append(Spacer(1, 10))

    if ai.get("business_impact"):
        story.append(Paragraph("Business Impact", styles["VLabel"]))
        story.append(Paragraph(_esc(ai.get("business_impact", "")), styles["VBody"]))
    story.append(PageBreak())

    # ── Security Headers ──────────────────────────────────
    story.append(Paragraph("Security Headers Analysis", styles["VSectionHead"]))
    headers_data = scan_data.get("headers", {})
    findings_list = headers_data.get("findings", []) if isinstance(headers_data, dict) else getattr(headers_data, "findings", [])
    if findings_list:
        rows = [["Header", "Status", "Severity"]]
        for f in findings_list:
            name = f.get("name","") if isinstance(f,dict) else getattr(f,"name","")
            status = f.get("status","") if isinstance(f,dict) else getattr(f,"status","")
            sev = f.get("severity","") if isinstance(f,dict) else getattr(f,"severity","")
            rows.append([_esc(str(name)), _esc(str(status)), _esc(str(sev))])
        story.append(_table(rows, [260, 90, 80]))
    story.append(Spacer(1, 16))

    # ── Open Ports ────────────────────────────────────────
    story.append(Paragraph("Open Ports", styles["VSectionHead"]))
    ports_data = scan_data.get("ports", {})
    open_ports = ports_data.get("open_ports", []) if isinstance(ports_data, dict) else []
    if open_ports:
        rows = [["Port", "Service", "Severity", "Description"]]
        for p in open_ports:
            rows.append([str(p.get("port","")), _esc(p.get("service","")),
                _esc(p.get("severity","")), _esc(str(p.get("description",""))[:60])])
        story.append(_table(rows, [50, 80, 80, 220]))
    else:
        story.append(Paragraph("No high-risk ports detected.", styles["VBody"]))
    story.append(Spacer(1, 16))

    # ── SSL/TLS ───────────────────────────────────────────
    story.append(Paragraph("SSL/TLS Analysis", styles["VSectionHead"]))
    ssl = scan_data.get("ssl_tls", {})
    if ssl:
        rows = [
            ["HTTPS Enabled", str(ssl.get("https_enabled", False))],
            ["TLS Version", str(ssl.get("tls_version", "N/A"))],
            ["Grade", str(ssl.get("grade", "N/A"))],
            ["Issuer", _esc(str(ssl.get("issuer","N/A"))[:80])],
            ["Expires", str(ssl.get("not_after","N/A"))],
            ["Days Remaining", str(ssl.get("days_remaining","N/A"))],
            ["Finding", _esc(str(ssl.get("finding","")))],
        ]
        t = Table(rows, colWidths=[130, 300])
        t.setStyle(TableStyle([
            ("FONTSIZE",(0,0),(-1,-1),10),
            ("TEXTCOLOR",(0,0),(0,-1),_hex("#555555")),
            ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
            ("BOTTOMPADDING",(0,0),(-1,-1),6),
            ("TOPPADDING",(0,0),(-1,-1),6),
            ("LINEBELOW",(0,0),(-1,-1),0.5,_hex("#eeeeee")),
        ]))
        story.append(t)
    story.append(Spacer(1, 16))

    # ── DNS ───────────────────────────────────────────────
    story.append(Paragraph("DNS & Email Security", styles["VSectionHead"]))
    dns = scan_data.get("dns", {})
    if dns:
        dns_findings = dns.get("findings", [])
        if dns_findings:
            rows = [["Finding", "Severity", "Description"]]
            for df in dns_findings:
                rows.append([_esc(df.get("name","")), _esc(df.get("severity","")), _esc(str(df.get("description",""))[:70])])
            story.append(_table(rows, [140, 80, 210]))
        else:
            story.append(Paragraph("No DNS security issues detected.", styles["VBody"]))
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"SPF: {_esc(str(dns.get('spf_record') or 'Missing'))}", styles["VBody"]))
        story.append(Paragraph(f"DMARC: {_esc(str(dns.get('dmarc_record') or 'Missing'))}", styles["VBody"]))
    story.append(PageBreak())

    # ── Cookies ───────────────────────────────────────────
    story.append(Paragraph("Cookie Security Analysis", styles["VSectionHead"]))
    cookies_data = scan_data.get("cookies", {})
    cookie_findings = cookies_data.get("findings", []) if isinstance(cookies_data, dict) else []
    if cookie_findings:
        rows = [["Cookie / Attribute", "Status", "Severity"]]
        for f in cookie_findings:
            name = f.get("name","") if isinstance(f,dict) else getattr(f,"name","")
            status = f.get("status","") if isinstance(f,dict) else getattr(f,"status","")
            sev = f.get("severity","") if isinstance(f,dict) else getattr(f,"severity","")
            rows.append([_esc(str(name)), _esc(str(status)), _esc(str(sev))])
        story.append(_table(rows, [260, 80, 90]))
    story.append(Spacer(1, 16))

    # ── Technologies ──────────────────────────────────────
    story.append(Paragraph("Technology Detection", styles["VSectionHead"]))
    tech_data = scan_data.get("technologies", {})
    techs = tech_data.get("technologies_detected", []) if isinstance(tech_data, dict) else []
    if techs:
        rows = [["Technology", "Version", "Source", "Severity"]]
        for t in techs:
            rows.append([_esc(t.get("name","")), _esc(str(t.get("version") or "-")),
                _esc(t.get("source","")), _esc(t.get("severity",""))])
        story.append(_table(rows, [150, 80, 120, 80]))
    else:
        story.append(Paragraph("No specific technologies detected.", styles["VBody"]))
    story.append(Spacer(1, 20))

    # ── Footer ────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=_hex("#dddddd")))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "<i>This report was generated by VAPTProX automated scanner. "
        "It is intended for authorized security testing only. "
        "All findings should be manually verified before remediation. "
        "Unauthorized scanning is illegal.</i>",
        styles["VDisclaimer"]
    ))

    doc.build(story)
    return os.path.abspath(filename)

