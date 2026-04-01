"""
Export utilities for phishing detection results.
Supports JSON, CSV, and PDF formats.
Provides both file-based and in-memory export for Streamlit.
"""

import csv
import json
import io
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional


def get_json_data(result: Dict[str, Any]) -> str:
    """Return result as JSON string (in-memory)."""
    return json.dumps(result, indent=2)


def get_csv_data(result: Dict[str, Any]) -> str:
    """Return result as CSV string (in-memory)."""
    url_info = result.get("context", {}).get("url", {})
    consistency = result.get("context", {}).get("consistency", {})
    signals = result.get("signals", result.get("context", {}).get("signals", {}))
    
    row = {
        "risk": result.get("risk_level", result.get("risk", "")),
        "confidence": result.get("overall_confidence", result.get("confidence", "")),
        "attack_type": result.get("attack_type", ""),
        "signals": json.dumps(signals) if isinstance(signals, dict) else str(signals),
        "categories": ", ".join(result.get("categories", [])),
        "url_domain": consistency.get("domain", ""),
        "url_malicious": url_info.get("malicious", False),
        "inconsistency_score": consistency.get("score", 0),
    }
    
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=row.keys())
    writer.writeheader()
    writer.writerow(row)
    return output.getvalue()


def get_pdf_data(result: Dict[str, Any], original_msg: str = "") -> bytes:
    """Return result as professional PDF report bytes (in-memory)."""
    try:
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
        from reportlab.lib import colors
        return _get_pdf_professional(result, original_msg)
    except ImportError:
        return _get_pdf_text(result, original_msg)


def _get_pdf_professional(result: Dict[str, Any], original_msg: str) -> bytes:
    """Generate professional PDF report using reportlab.platypus."""
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    styles = getSampleStyleSheet()
    story = []
    
    # Custom styles
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, 
                                  textColor=colors.HexColor('#1a365d'), alignment=TA_CENTER)
    section_style = ParagraphStyle('Section', parent=styles['Heading2'], fontSize=13,
                                    textColor=colors.HexColor('#2c5282'), spaceBefore=12, spaceAfter=6)
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=10, spaceAfter=4)
    bullet_style = ParagraphStyle('Bullet', parent=styles['Normal'], fontSize=10, 
                                   leftIndent=20, spaceAfter=3)
    message_style = ParagraphStyle('Message', parent=styles['Normal'], fontSize=9,
                                    backColor=colors.HexColor('#f7fafc'), leftIndent=10,
                                    rightIndent=10, spaceBefore=6, spaceAfter=6)
    
    # Extract data
    url_info = result.get("context", {}).get("url", {})
    consistency = result.get("context", {}).get("consistency", {})
    signals = result.get("signals", result.get("context", {}).get("signals", {}))
    risk = str(result.get("risk_level", result.get("risk", "N/A"))).upper()
    conf = result.get("overall_confidence", result.get("confidence", 0))
    if isinstance(conf, dict):
        conf = conf.get("overall", 0)
    attack_type = result.get("attack_type", "Not Identified")
    
    # Generate report ID
    timestamp = datetime.now()
    report_id = hashlib.md5(f"{timestamp.isoformat()}{original_msg[:50]}".encode()).hexdigest()[:8].upper()
    
    # 1. HEADER
    story.append(Paragraph("SocEngDetect Report", title_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<font size=9 color='#718096'>Report ID: {report_id} | Generated: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}</font>", 
                           ParagraphStyle('Meta', alignment=TA_CENTER)))
    story.append(Spacer(1, 12))
    
    # 2. ANALYZED MESSAGE
    if original_msg:
        story.append(Paragraph("Analyzed Message", section_style))
        safe_msg = original_msg.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        safe_msg = safe_msg.replace('\n', '<br/>')
        story.append(Paragraph(safe_msg, message_style))
        story.append(Spacer(1, 8))
    
    # 3. DETECTION SUMMARY
    story.append(Paragraph("Detection Summary", section_style))
    
    risk_colors = {"HIGH": "#e53e3e", "POTENTIAL": "#dd6b20", "LOW": "#3182ce", "SAFE": "#38a169"}
    risk_color = risk_colors.get(risk, "#718096")
    
    summary_data = [
        ["Risk Level", f"<font color='{risk_color}'><b>{risk}</b></font>"],
        ["Confidence", f"{conf:.0f}%" if isinstance(conf, (int, float)) else str(conf)],
        ["Attack Type", attack_type or "Not Identified"],
    ]
    
    for label, value in summary_data:
        story.append(Paragraph(f"<b>{label}:</b> {value}", body_style))
    story.append(Spacer(1, 8))
    
    # 4. KEY INDICATORS (signals > 0.3)
    story.append(Paragraph("Key Indicators", section_style))
    strong_signals = []
    
    signal_labels = {
        "urgency": "Urgency pressure detected",
        "impersonation": "Impersonation tactics present",
        "authority": "Authority manipulation detected",
        "fear_threat": "Fear/threat language used",
        "reward_lure": "Reward/lure tactics present",
        "inconsistency": "Content inconsistencies found"
    }
    
    if isinstance(signals, dict):
        for key, value in signals.items():
            if key.startswith("_"):
                continue
            score = value.get("score", value) if isinstance(value, dict) else value
            if isinstance(score, (int, float)) and score > 0.3:
                confidence = "high" if score > 0.6 else "moderate"
                label = signal_labels.get(key, key.replace("_", " ").title())
                strong_signals.append(f"• {label} ({confidence} confidence)")
    
    if strong_signals:
        for sig in strong_signals[:5]:
            story.append(Paragraph(sig, bullet_style))
    else:
        story.append(Paragraph("• No significant threat indicators detected", bullet_style))
    story.append(Spacer(1, 8))
    
    # 5. URL ANALYSIS (if exists)
    domain = consistency.get("domain", "")
    if domain or url_info.get("malicious") or url_info.get("urls"):
        story.append(Paragraph("URL Analysis", section_style))
        if domain:
            story.append(Paragraph(f"<b>Domain:</b> {domain}", body_style))
        story.append(Paragraph(f"<b>Malicious:</b> {'Yes' if url_info.get('malicious') else 'No'}", body_style))
        story.append(Paragraph(f"<b>Trusted:</b> {'Yes' if url_info.get('trusted') else 'No'}", body_style))
        story.append(Spacer(1, 8))
    
    # 6. CONSISTENCY CHECK
    story.append(Paragraph("Consistency Check", section_style))
    cons_score = consistency.get("score", 0)
    cons_signals = consistency.get("signals", [])
    
    if cons_score > 0 or cons_signals:
        story.append(Paragraph(f"<b>Score:</b> {cons_score}", body_style))
        if cons_signals:
            story.append(Paragraph("Brand or context mismatch detected", body_style))
            for sig in cons_signals[:3]:
                story.append(Paragraph(f"• {sig}", bullet_style))
    else:
        story.append(Paragraph("No inconsistencies detected", body_style))
    story.append(Spacer(1, 8))
    
    # 7. ANALYSIS INSIGHTS
    story.append(Paragraph("Analysis Insights", section_style))
    insights = []
    
    if risk in ["HIGH", "POTENTIAL"]:
        if attack_type and attack_type != "Not Identified":
            insights.append(f"Message patterns match known {attack_type.lower()} attempts")
        if strong_signals:
            insights.append("Multiple manipulation techniques detected in message content")
        if url_info.get("malicious"):
            insights.append("Contains links to potentially dangerous domains")
    else:
        insights.append("Message does not exhibit strong phishing characteristics")
        insights.append("Low similarity to known attack patterns in database")
    
    for insight in insights[:3]:
        story.append(Paragraph(f"• {insight}", bullet_style))
    story.append(Spacer(1, 10))
    
    # 8. RECOMMENDATIONS
    story.append(Paragraph("Recommended Actions", section_style))
    
    if risk in ["HIGH", "POTENTIAL"]:
        story.append(Paragraph("<b>What You Should Do:</b>", body_style))
        dos = [
            "Verify sender identity through official channels",
            "Access accounts directly via official website (not through links)",
            "Report suspicious message to IT/security team",
            "Contact the claimed organization using verified contact info"
        ]
        for tip in dos[:3]:
            story.append(Paragraph(f"• {tip}", bullet_style))
        
        story.append(Spacer(1, 6))
        story.append(Paragraph("<b>What to Avoid:</b>", body_style))
        donts = [
            "Do not click any links in the message",
            "Do not enter credentials or personal information",
            "Do not download any attachments",
            "Do not reply with sensitive information"
        ]
        for tip in donts[:3]:
            story.append(Paragraph(f"• {tip}", bullet_style))
    else:
        story.append(Paragraph("• Message appears safe, but always verify unexpected requests", bullet_style))
        story.append(Paragraph("• When in doubt, contact the sender through known channels", bullet_style))
    
    # Footer
    story.append(Spacer(1, 20))
    story.append(Paragraph("<font size=8 color='#a0aec0'>Generated by Social Engineering Detection System | This is an automated analysis</font>",
                           ParagraphStyle('Footer', alignment=TA_CENTER)))
    
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def _get_pdf_text(result: Dict[str, Any], original_msg: str = "") -> bytes:
    """Fallback: generate plain text as bytes."""
    url_info = result.get("context", {}).get("url", {})
    consistency = result.get("context", {}).get("consistency", {})
    signals = result.get("signals", result.get("context", {}).get("signals", {}))
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    risk = str(result.get("risk_level", result.get("risk", 'N/A'))).upper()
    conf = result.get("overall_confidence", result.get("confidence", 0))
    if isinstance(conf, dict):
        conf = conf.get("overall", 0)
    
    lines = [
        "=" * 50,
        "SOCENGDETECT REPORT",
        "=" * 50,
        f"Generated: {timestamp}",
        "",
        "ANALYZED MESSAGE",
        "-" * 30,
        original_msg if original_msg else "(No message provided)",
        "",
        "DETECTION SUMMARY",
        "-" * 30,
        f"Risk Level: {risk}",
        f"Confidence: {conf:.0f}%" if isinstance(conf, (int, float)) else f"Confidence: {conf}",
        f"Attack Type: {result.get('attack_type', 'Not Identified')}",
        "",
        "KEY INDICATORS",
        "-" * 30,
    ]
    
    found_signals = False
    if isinstance(signals, dict):
        for key, value in signals.items():
            if key.startswith("_"):
                continue
            score = value.get("score", value) if isinstance(value, dict) else value
            if isinstance(score, (int, float)) and score > 0.3:
                conf_level = "high" if score > 0.6 else "moderate"
                lines.append(f"  • {key.replace('_', ' ').title()} ({conf_level})")
                found_signals = True
    
    if not found_signals:
        lines.append("  • No significant indicators detected")
    
    lines.extend([
        "",
        "CONSISTENCY CHECK",
        "-" * 30,
        f"Score: {consistency.get('score', 0)}",
    ])
    
    cons_signals = consistency.get("signals", [])
    if cons_signals:
        lines.append("Issues: " + ", ".join(cons_signals))
    else:
        lines.append("No inconsistencies detected")
    
    lines.extend([
        "",
        "RECOMMENDED ACTIONS",
        "-" * 30,
    ])
    
    if risk in ["HIGH", "POTENTIAL"]:
        lines.extend([
            "Do:",
            "  • Verify sender through official channels",
            "  • Report to IT/security team",
            "Avoid:",
            "  • Clicking links in message",
            "  • Entering credentials or personal info",
        ])
    else:
        lines.extend([
            "  • Message appears safe",
            "  • Always verify unexpected requests",
        ])
    
    lines.extend(["", "=" * 50])
    
    return "\n".join(lines).encode("utf-8")


def export_to_json(result: Dict[str, Any], filename: str = "output.json") -> str:
    """Export result to JSON file."""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    return filename


def export_to_csv(result: Dict[str, Any], filename: str = "output.csv") -> str:
    """Export result to CSV file (flattened structure)."""
    csv_data = get_csv_data(result)
    with open(filename, "w", newline="", encoding="utf-8") as f:
        f.write(csv_data)
    return filename


def export_to_pdf(result: Dict[str, Any], filename: str = "output.pdf") -> str:
    """Export result to PDF file."""
    pdf_data = get_pdf_data(result)
    with open(filename, "wb") as f:
        f.write(pdf_data)
    return filename


def export_result(result: Dict[str, Any], format: str = "json", filename: str = None) -> str:
    """
    Export result in specified format (file-based).
    
    Args:
        result: Detection result dictionary
        format: "json" | "csv" | "pdf"
        filename: Output filename (auto-generated if None)
    
    Returns:
        Path to exported file
    """
    if filename is None:
        filename = f"output.{format}"
    
    if format == "json":
        return export_to_json(result, filename)
    elif format == "csv":
        return export_to_csv(result, filename)
    elif format == "pdf":
        return export_to_pdf(result, filename)
    else:
        raise ValueError(f"Unsupported format: {format}. Use 'json', 'csv', or 'pdf'.")
