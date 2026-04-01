"""
Export utilities for phishing detection results.
Supports JSON, CSV, and PDF formats.
Provides both file-based and in-memory export for Streamlit.
"""

import csv
import json
import io
from typing import Dict, Any, Union


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


def get_pdf_data(result: Dict[str, Any]) -> bytes:
    """Return result as PDF bytes (in-memory)."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        return _get_pdf_reportlab(result)
    except ImportError:
        return _get_pdf_text(result)


def _get_pdf_reportlab(result: Dict[str, Any]) -> bytes:
    """Generate PDF using reportlab (in-memory)."""
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - 50
    
    url_info = result.get("context", {}).get("url", {})
    consistency = result.get("context", {}).get("consistency", {})
    signals = result.get("signals", result.get("context", {}).get("signals", {}))
    
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "Phishing Detection Report")
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(50, y, "-" * 50)
    y -= 30
    
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Risk Level:")
    c.setFont("Helvetica", 12)
    c.drawString(150, y, str(result.get("risk_level", result.get("risk", "N/A"))))
    y -= 20
    
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Confidence:")
    c.setFont("Helvetica", 12)
    conf = result.get("overall_confidence", result.get("confidence", 0))
    c.drawString(150, y, f"{conf:.2f}" if isinstance(conf, (int, float)) else str(conf))
    y -= 30
    
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Attack Type:")
    y -= 15
    c.setFont("Helvetica", 11)
    c.drawString(70, y, str(result.get("attack_type", "N/A")))
    y -= 25
    
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Signals:")
    y -= 15
    c.setFont("Helvetica", 10)
    if isinstance(signals, dict):
        for key, value in signals.items():
            if not key.startswith("_"):
                c.drawString(70, y, f"{key}: {value}")
                y -= 12
                if y < 100:
                    c.showPage()
                    y = height - 50
    y -= 10
    
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Categories:")
    y -= 15
    c.setFont("Helvetica", 11)
    cats = result.get("categories", [])
    c.drawString(70, y, ", ".join(cats) if cats else "None")
    y -= 25
    
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "URL Analysis:")
    y -= 15
    c.setFont("Helvetica", 10)
    c.drawString(70, y, f"Domain: {consistency.get('domain', 'N/A')}")
    y -= 12
    c.drawString(70, y, f"Malicious: {url_info.get('malicious', False)}")
    y -= 12
    c.drawString(70, y, f"Trusted: {url_info.get('trusted', False)}")
    y -= 25
    
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Consistency Check:")
    y -= 15
    c.setFont("Helvetica", 10)
    c.drawString(70, y, f"Score: {consistency.get('score', 0)}")
    y -= 12
    cons_signals = consistency.get("signals", [])
    if cons_signals:
        c.drawString(70, y, f"Issues: {', '.join(cons_signals)}")
    
    c.save()
    buffer.seek(0)
    return buffer.getvalue()


def _get_pdf_text(result: Dict[str, Any]) -> bytes:
    """Fallback: generate plain text as bytes."""
    url_info = result.get("context", {}).get("url", {})
    consistency = result.get("context", {}).get("consistency", {})
    signals = result.get("signals", result.get("context", {}).get("signals", {}))
    
    lines = [
        "Phishing Detection Report",
        "-" * 30,
        "",
        f"Risk: {result.get('risk_level', result.get('risk', 'N/A'))}",
        f"Confidence: {result.get('overall_confidence', result.get('confidence', 0)):.2f}",
        "",
        "Attack Type:",
        f"  {result.get('attack_type', 'N/A')}",
        "",
        "Signals:",
    ]
    
    if isinstance(signals, dict):
        for key, value in signals.items():
            if not key.startswith("_"):
                lines.append(f"  {key}: {value}")
    
    lines.extend([
        "",
        "Categories:",
        f"  {', '.join(result.get('categories', [])) or 'None'}",
        "",
        "URL:",
        f"  domain: {consistency.get('domain', 'N/A')}",
        f"  malicious: {url_info.get('malicious', False)}",
        "",
        "Consistency:",
        f"  score: {consistency.get('score', 0)}",
        f"  signals: {', '.join(consistency.get('signals', [])) or 'None'}",
    ])
    
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
