"""AEGIS PDF Report Generator — Military-grade branded incident reports."""
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch, mm
from reportlab.lib.colors import HexColor, white, black
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas
from io import BytesIO
from datetime import datetime


# Colors
NAVY = HexColor("#0a0f1e")
DARK_BG = HexColor("#111827")
ACCENT_BLUE = HexColor("#3b82f6")
CRITICAL_RED = HexColor("#ef4444")
MEDIUM_AMBER = HexColor("#f59e0b")
LOW_GREEN = HexColor("#10b981")
TEXT_PRIMARY = HexColor("#f1f5f9")
TEXT_SECONDARY = HexColor("#94a3b8")
BORDER = HexColor("#1e293b")


class AegisReportCanvas(canvas.Canvas):
    """Custom canvas with AEGIS branding on every page."""

    def __init__(self, *args, **kwargs):
        self.scan_id = kwargs.pop("scan_id", "AEG-2026-001")
        super().__init__(*args, **kwargs)
        self.pages = []

    def showPage(self):
        self.pages.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self.pages)
        for idx, page in enumerate(self.pages):
            self.__dict__.update(page)
            self._draw_footer(idx + 1, num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def _draw_footer(self, page_num, total_pages):
        self.saveState()
        self.setFillColor(HexColor("#64748b"))
        self.setFont("Helvetica", 8)
        self.drawString(40, 25, f"AEGIS v1.0 | CLASSIFIED | {self.scan_id}")
        self.drawRightString(A4[0] - 40, 25, f"Page {page_num} of {total_pages}")
        # Top border line
        self.setStrokeColor(HexColor("#1e293b"))
        self.setLineWidth(0.5)
        self.line(40, A4[1] - 40, A4[0] - 40, A4[1] - 40)
        # Bottom border line
        self.line(40, 40, A4[0] - 40, 40)
        self.restoreState()


def generate_pdf_report(scan_data: dict) -> bytes:
    """Generate a complete AEGIS incident report PDF."""
    buffer = BytesIO()
    scan_id = scan_data.get("scan_id", f"AEG-2026-{datetime.now().strftime('%m%d')}-001")

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=50,
        bottomMargin=50
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "AegisTitle",
        parent=styles["Title"],
        fontSize=28,
        textColor=HexColor("#1e293b"),
        alignment=TA_CENTER,
        spaceAfter=12,
        fontName="Helvetica-Bold"
    )

    heading_style = ParagraphStyle(
        "AegisHeading",
        parent=styles["Heading1"],
        fontSize=16,
        textColor=HexColor("#0a0f1e"),
        spaceBefore=20,
        spaceAfter=10,
        fontName="Helvetica-Bold"
    )

    subheading_style = ParagraphStyle(
        "AegisSubheading",
        parent=styles["Heading2"],
        fontSize=12,
        textColor=HexColor("#3b82f6"),
        spaceBefore=14,
        spaceAfter=8,
        fontName="Helvetica-Bold"
    )

    body_style = ParagraphStyle(
        "AegisBody",
        parent=styles["Normal"],
        fontSize=10,
        textColor=HexColor("#374151"),
        leading=14,
        spaceAfter=6,
    )

    mono_style = ParagraphStyle(
        "AegisMono",
        parent=styles["Normal"],
        fontSize=9,
        textColor=HexColor("#3b82f6"),
        fontName="Courier",
        leading=12,
    )

    classified_style = ParagraphStyle(
        "AegisClassified",
        parent=styles["Normal"],
        fontSize=12,
        textColor=HexColor("#ef4444"),
        alignment=TA_CENTER,
        fontName="Courier-Bold",
        spaceBefore=20,
    )

    center_style = ParagraphStyle(
        "AegisCenter",
        parent=styles["Normal"],
        fontSize=10,
        textColor=HexColor("#64748b"),
        alignment=TA_CENTER,
        spaceAfter=6,
    )

    elements = []

    # ===== PAGE 1: COVER =====
    elements.append(Spacer(1, 80))
    elements.append(Paragraph("◆ AEGIS ◆", title_style))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("ADVANCED ENGINE FOR GUIDED INTELLIGENCE & SURVEILLANCE", ParagraphStyle(
        "CoverSub", parent=styles["Normal"], fontSize=10, textColor=HexColor("#64748b"),
        alignment=TA_CENTER, fontName="Courier", letterSpacing=2
    )))
    elements.append(Spacer(1, 40))
    elements.append(Paragraph("INCIDENT REPORT", ParagraphStyle(
        "CoverMain", parent=styles["Title"], fontSize=24, textColor=HexColor("#0a0f1e"),
        alignment=TA_CENTER, fontName="Helvetica-Bold"
    )))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("CONFIDENTIAL — EYES ONLY", classified_style))
    elements.append(Spacer(1, 40))

    # Metadata table
    metrics = scan_data.get("metrics", {})
    severity = metrics.get("overall_severity", "MEDIUM")
    meta_data = [
        ["SCAN ID", scan_id],
        ["DATE", datetime.now().strftime("%Y-%m-%d %H:%M UTC")],
        ["CLASSIFICATION", severity],
        ["TOTAL THREATS", str(metrics.get("total_threats", 0))],
        ["CRITICAL ALERTS", str(metrics.get("critical_count", 0))],
        ["THREAT SCORE", f"{metrics.get('overall_threat_score', 0)}/100"],
    ]
    meta_table = Table(meta_data, colWidths=[150, 300])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Courier-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Courier"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), HexColor("#64748b")),
        ("TEXTCOLOR", (1, 0), (1, -1), HexColor("#1e293b")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 0), (-1, -2), 0.5, HexColor("#e2e8f0")),
        ("ALIGN", (0, 0), (0, -1), "RIGHT"),
        ("ALIGN", (1, 0), (1, -1), "LEFT"),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 40))
    elements.append(Paragraph(f"Generated by AEGIS AI Engine v2.1 • {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC", center_style))
    elements.append(PageBreak())

    # ===== PAGE 2: EXECUTIVE SUMMARY =====
    elements.append(Paragraph("EXECUTIVE SUMMARY", heading_style))

    elements.append(Paragraph("COMMANDER'S BRIEF", subheading_style))
    brief = scan_data.get("commander_brief", {})
    for line in brief.get("lines", []):
        elements.append(Paragraph(f"▸ {line}", body_style))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("KEY METRICS", subheading_style))
    metric_data = [
        ["Total Threats", str(metrics.get("total_threats", 0)),
         "Critical Alerts", str(metrics.get("critical_count", 0))],
        ["Unique Attacker IPs", str(metrics.get("unique_ips", 0)),
         "Scan Duration", f"{metrics.get('scan_duration', 0)}s"],
    ]
    metric_table = Table(metric_data, colWidths=[120, 100, 120, 100])
    metric_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
        ("FONTNAME", (3, 0), (3, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("FONTSIZE", (1, 0), (1, -1), 14),
        ("FONTSIZE", (3, 0), (3, -1), 14),
        ("TEXTCOLOR", (0, 0), (0, -1), HexColor("#64748b")),
        ("TEXTCOLOR", (2, 0), (2, -1), HexColor("#64748b")),
        ("TEXTCOLOR", (1, 0), (1, -1), HexColor("#0a0f1e")),
        ("TEXTCOLOR", (3, 0), (3, -1), HexColor("#0a0f1e")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
    ]))
    elements.append(metric_table)
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("RISK ASSESSMENT", subheading_style))
    score = metrics.get("overall_threat_score", 0)
    sev = metrics.get("overall_severity", "LOW")
    elements.append(Paragraph(
        f"Overall Threat Score: <b>{score}/100</b> — Classification: <b>{sev}</b>",
        body_style
    ))
    elements.append(PageBreak())

    # ===== PAGE 3: THREAT INVENTORY =====
    elements.append(Paragraph("THREAT INVENTORY", heading_style))
    threats = scan_data.get("threats", [])

    if threats:
        table_data = [["#", "Timestamp", "Source IP", "Type", "Severity", "MITRE"]]
        for t in threats[:50]:  # Cap at 50 for PDF
            table_data.append([
                str(t["id"]),
                str(t["timestamp"])[:19],
                t["source_ip"],
                t["threat_type"],
                t["severity"],
                t["mitre_code"]
            ])

        threat_table = Table(table_data, colWidths=[25, 100, 90, 90, 60, 55])
        style_commands = [
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("FONTNAME", (0, 1), (-1, -1), "Courier"),
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#0a0f1e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.25, HexColor("#e2e8f0")),
            ("ALIGN", (0, 0), (0, -1), "CENTER"),
            ("ALIGN", (4, 0), (4, -1), "CENTER"),
            ("ALIGN", (5, 0), (5, -1), "CENTER"),
        ]

        # Color severity cells
        for i, t in enumerate(threats[:50], 1):
            if t["severity"] == "CRITICAL":
                style_commands.append(("TEXTCOLOR", (4, i), (4, i), HexColor("#ef4444")))
                style_commands.append(("FONTNAME", (4, i), (4, i), "Courier-Bold"))
            elif t["severity"] == "MEDIUM":
                style_commands.append(("TEXTCOLOR", (4, i), (4, i), HexColor("#f59e0b")))
            else:
                style_commands.append(("TEXTCOLOR", (4, i), (4, i), HexColor("#10b981")))

            # Alternate row colors
            if i % 2 == 0:
                style_commands.append(("BACKGROUND", (0, i), (-1, i), HexColor("#f8fafc")))

        threat_table.setStyle(TableStyle(style_commands))
        elements.append(threat_table)
    elements.append(PageBreak())

    # ===== PAGE 4: ATTACK TIMELINE =====
    elements.append(Paragraph("ATTACK TIMELINE", heading_style))
    timeline = scan_data.get("timeline", threats[:20])
    for t in timeline[:20]:
        sev_color = "#ef4444" if t["severity"] == "CRITICAL" else "#f59e0b" if t["severity"] == "MEDIUM" else "#10b981"
        elements.append(Paragraph(
            f'<font color="#3b82f6" face="Courier" size="8">{str(t["timestamp"])[:19]}</font>  '
            f'<font color="{sev_color}" face="Courier-Bold" size="8">[{t["severity"]}]</font>  '
            f'{t["threat_type"]} — {t["mitre_code"]} · {t["mitre_technique"]}',
            body_style
        ))
        elements.append(Paragraph(
            f'<font color="#64748b" size="8">Source: {t["source_ip"]} ({t["country"]}) → {t["dest_ip"]}</font>',
            body_style
        ))
        elements.append(Spacer(1, 4))
    elements.append(PageBreak())

    # ===== PAGE 5: AI ANALYSIS =====
    elements.append(Paragraph("AI INTELLIGENCE ANALYSIS", heading_style))
    critical_threats = [t for t in threats if t["severity"] == "CRITICAL"][:10]
    for t in critical_threats:
        elements.append(Paragraph(
            f'<b>{t["threat_type"]}</b> — {t["mitre_code"]} · {t["mitre_technique"]}',
            subheading_style
        ))
        elements.append(Paragraph(t["ai_explanation"], body_style))
        elements.append(Spacer(1, 6))
    elements.append(PageBreak())

    # ===== PAGE 6: IP INTELLIGENCE =====
    elements.append(Paragraph("IP INTELLIGENCE", heading_style))
    seen_ips = set()
    ip_data = [["Source IP", "Country", "City", "ISP", "Threats"]]
    for t in threats:
        if t["source_ip"] not in seen_ips and t["country"] != "Internal":
            seen_ips.add(t["source_ip"])
            count = sum(1 for x in threats if x["source_ip"] == t["source_ip"])
            ip_data.append([t["source_ip"], t["country"], t["city"], t["isp"], str(count)])
            if len(seen_ips) >= 30:
                break

    if len(ip_data) > 1:
        ip_table = Table(ip_data, colWidths=[90, 70, 70, 120, 50])
        ip_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("FONTNAME", (0, 1), (-1, -1), "Courier"),
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#0a0f1e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), white),
            ("GRID", (0, 0), (-1, -1), 0.25, HexColor("#e2e8f0")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(ip_table)
    elements.append(PageBreak())

    # ===== PAGE 7: RECOMMENDATIONS =====
    elements.append(Paragraph("RECOMMENDED ACTIONS", heading_style))

    elements.append(Paragraph("IMMEDIATE ACTIONS", subheading_style))
    immediate = [
        "Block all CRITICAL-classified source IPs at the perimeter firewall",
        "Force credential reset for all accounts targeted by brute force attacks",
        "Isolate compromised hosts showing data exfiltration indicators",
        "Enable enhanced logging on all network boundary devices"
    ]
    for action in immediate:
        elements.append(Paragraph(f"▸ {action}", body_style))

    elements.append(Paragraph("SHORT-TERM ACTIONS (24-72 HOURS)", subheading_style))
    short_term = [
        "Deploy updated IDS/IPS signatures for detected attack patterns",
        "Conduct vulnerability assessment on all services targeted during scan",
        "Review and update firewall rules based on identified attack vectors",
        "Brief security operations team on detected MITRE ATT&CK techniques"
    ]
    for action in short_term:
        elements.append(Paragraph(f"▸ {action}", body_style))

    elements.append(Paragraph("LONG-TERM ACTIONS (1-4 WEEKS)", subheading_style))
    long_term = [
        "Implement zero-trust network architecture for critical segments",
        "Deploy deception technology (honeypots) on identified lateral movement paths",
        "Conduct comprehensive security audit of externally facing services",
        "Establish regular threat intelligence sharing with sector partners"
    ]
    for action in long_term:
        elements.append(Paragraph(f"▸ {action}", body_style))

    # Build PDF
    doc.build(
        elements,
        canvasmaker=lambda *args, **kwargs: AegisReportCanvas(*args, scan_id=scan_id, **kwargs)
    )

    return buffer.getvalue()
