
from pathlib import Path
import re
import sqlite3
from io import BytesIO
from xml.sax.saxutils import escape as xml_escape

import joblib
from flask import Flask, render_template, request, redirect, url_for, make_response

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishguard_model.joblib"
DATABASE_PATH = BASE_DIR / "phishguard_history.db"

app = Flask(__name__)

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        "Model not found. Run train_model.py first."
    )

model = joblib.load(MODEL_PATH)


def get_db():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_db() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                prediction TEXT NOT NULL,
                phishing_score REAL NOT NULL,
                email_preview TEXT NOT NULL
            )
        """)


initialize_database()


def analyze_indicators(email_text):
    indicators = []

    urls = re.findall(
        r"""https?://[^\s<>"']+|www\.[^\s<>"']+""",
        email_text,
        flags=re.IGNORECASE,
    )

    if urls:
        indicators.append(
            f"Contains {len(urls)} URL(s). Check each link carefully."
        )

    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "expires today",
        "account suspended",
        "final warning",
    ]

    found_urgency = [
        word for word in urgency_words
        if word in email_text.lower()
    ]

    if found_urgency:
        indicators.append(
            "Urgency-related language: "
            + ", ".join(found_urgency)
        )

    sensitive_phrases = [
        "enter your password",
        "verify your password",
        "confirm your password",
        "share your otp",
        "send your otp",
        "provide your credit card",
        "verify your account",
    ]

    found_sensitive = [
        phrase for phrase in sensitive_phrases
        if phrase in email_text.lower()
    ]

    if found_sensitive:
        indicators.append(
            "Potential sensitive-information request: "
            + ", ".join(found_sensitive)
        )

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
    ]

    if any(
        shortener in url.lower()
        for url in urls
        for shortener in shorteners
    ):
        indicators.append(
            "Contains a shortened URL that hides the destination."
        )

    if not indicators:
        indicators.append(
            "No warning signs from these basic rules were detected."
        )

    return indicators


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    phishing_score = None
    email_text = ""
    indicators = []

    if request.method == "POST":
        email_text = request.form.get(
            "email_text", ""
        ).strip()

        if email_text:
            prediction = model.predict([email_text])[0]
            probabilities = model.predict_proba([email_text])[0]

            classes = list(
                model.named_steps["classifier"].classes_
            )

            phishing_score = round(
                float(
                    probabilities[classes.index(1)]
                ) * 100,
                1,
            )

            result = (
                "PHISHING-LIKE"
                if prediction == 1
                else "LEGITIMATE-LIKE"
            )

            indicators = analyze_indicators(email_text)

            # Store a short preview, not the full email.
            preview = " ".join(email_text.split())[:120]

            with get_db() as connection:
                connection.execute(
                    """
                    INSERT INTO scan_history
                    (timestamp, prediction, phishing_score, email_preview)
                    VALUES (datetime('now', 'localtime'), ?, ?, ?)
                    """,
                    (result, phishing_score, preview),
                )

    with get_db() as connection:
        total_scans = connection.execute(
            "SELECT COUNT(*) FROM scan_history"
        ).fetchone()[0]
        
        legitimate_count = connection.execute(
            """
            SELECT COUNT(*) FROM scan_history
            WHERE prediction = 'LEGITIMATE-LIKE'
            """
        ).fetchone()[0]


        phishing_count = connection.execute(
            """
            SELECT COUNT(*) FROM scan_history
            WHERE prediction = 'PHISHING-LIKE'
            """
        ).fetchone()[0]

        recent_scans = connection.execute(
            """
            SELECT id, timestamp, prediction,
                   phishing_score, email_preview
            FROM scan_history
            ORDER BY id DESC
            LIMIT 10
            """
        ).fetchall()

    return render_template(
        "index.html",
        result=result,
        phishing_score=phishing_score,
        email_text=email_text,
        indicators=indicators,
        total_scans=total_scans,
        phishing_count=phishing_count,
        legitimate_count=legitimate_count,
        recent_scans=recent_scans,
    )



@app.route("/download-report", methods=["POST"])
def download_report():
    from html import escape
    from datetime import datetime

    email_text = request.form.get("email_text", "").strip()

    if not email_text:
        return redirect(url_for("home"))

    # Run the existing machine-learning model
    prediction = model.predict([email_text])[0]
    probabilities = model.predict_proba([email_text])[0]

    classes = list(model.named_steps["classifier"].classes_)

    phishing_score = round(
        float(probabilities[classes.index(1)]) * 100,
        1,
    )

    result = (
        "PHISHING-LIKE"
        if prediction == 1
        else "LEGITIMATE-LIKE"
    )

    # Run the existing security warning checks
    indicators = analyze_indicators(email_text)

    scan_time = datetime.now().astimezone().strftime(
        "%d %B %Y, %I:%M:%S %p %Z"
    )

    # Escape user-supplied content before inserting it into HTML
    safe_email = escape(email_text)
    safe_result = escape(result)
    safe_indicators = "".join(
        f"<li>{escape(indicator)}</li>"
        for indicator in indicators
    )

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>PhishGuard Email Analysis Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 850px;
            margin: 35px auto;
            padding: 25px;
            line-height: 1.6;
            color: #222;
            background: #f4f6f9;
        }}
        .report {{
            background: white;
            padding: 30px;
            border-radius: 12px;
            border: 1px solid #ddd;
        }}
        h1 {{ color: #173b70; }}
        .result {{
            padding: 12px;
            background: #eef3fa;
            border-radius: 6px;
            font-weight: bold;
        }}
        .email {{
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            background: #f5f5f5;
            padding: 15px;
            border-radius: 6px;
        }}
        .warning {{ color: #9a3412; }}
        .disclaimer {{
            margin-top: 25px;
            font-size: 13px;
            color: #555;
        }}
        @media print {{
            body {{ background: white; margin: 0; }}
            .report {{ border: none; }}
        }}
    </style>
</head>
<body>
<div class="report">
    <h1>PhishGuard</h1>
    <h2>Email Security Analysis Report</h2>
    <p><strong>Scan date and time:</strong> {escape(scan_time)}</p>

    <h3>Analysis Result</h3>
    <p class="result">{safe_result}</p>
    <p><strong>Phishing probability score:</strong> {phishing_score}%</p>

    <h3>Security Warning Indicators</h3>
    <ul class="warning">{safe_indicators}</ul>

    <h3>Analysed Email</h3>
    <div class="email">{safe_email}</div>

    <p class="disclaimer">
        Disclaimer: This report is generated by a demonstration
        phishing-detection system. Model predictions and rule-based
        indicators can be incorrect. Do not treat this report alone
        as proof that an email is safe or malicious.
    </p>
</div>
</body>
</html>
"""

    response = make_response(report_html)
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    response.headers["Content-Disposition"] = (
        'attachment; filename="PhishGuard_Analysis_Report.html"'
    )

    return response

@app.route("/download-pdf", methods=["POST"])
def download_pdf():
    from datetime import datetime

    email_text = request.form.get("email_text", "").strip()

    if not email_text:
        return redirect(url_for("home"))

    # Run the existing machine-learning model
    prediction = model.predict([email_text])[0]
    probabilities = model.predict_proba([email_text])[0]
    classes = list(model.named_steps["classifier"].classes_)

    phishing_score = round(
        float(probabilities[classes.index(1)]) * 100,
        1,
    )

    result = (
        "PHISHING-LIKE"
        if prediction == 1
        else "LEGITIMATE-LIKE"
    )

    indicators = analyze_indicators(email_text)
    scan_time = datetime.now().astimezone().strftime(
        "%d %B %Y, %I:%M:%S %p %Z"
    )

    # Create a PDF in memory
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        Preformatted,
    )

    pdf_buffer = BytesIO()

    document = SimpleDocTemplate(
        pdf_buffer,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="PhishGuard Email Analysis Report",
        author="PhishGuard",
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#173B70"),
        spaceAfter=12,
    ))
    styles.add(ParagraphStyle(
        name="SmallNote",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#555555"),
    ))

    story = [
        Paragraph("PhishGuard", styles["ReportTitle"]),
        Paragraph("Email Security Analysis Report", styles["Heading2"]),
        Spacer(1, 8),
        Paragraph(
            f"<b>Scan date and time:</b> {xml_escape(scan_time)}",
            styles["BodyText"],
        ),
        Spacer(1, 12),
        Paragraph("Analysis Result", styles["Heading2"]),
    ]

    result_table = Table(
        [[Paragraph(
            f"<b>{xml_escape(result)}</b>",
            styles["BodyText"],
        )], [
            Paragraph(
                f"<b>Phishing probability score:</b> {phishing_score}%",
                styles["BodyText"],
            )
        ]],
        colWidths=[165 * mm],
    )

    result_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EEF3FA")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCD6E5")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))

    story.extend([
        result_table,
        Spacer(1, 14),
        Paragraph("Security Warning Indicators", styles["Heading2"]),
    ])

    for indicator in indicators:
        story.append(Paragraph(
            "&#8226; " + xml_escape(indicator),
            styles["BodyText"],
        ))
        story.append(Spacer(1, 4))

    story.extend([
        Spacer(1, 10),
        Paragraph("Analysed Email", styles["Heading2"]),
        Paragraph(
    xml_escape(email_text).replace("\n", "<br/>"),
    ParagraphStyle(
        "EmailText",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        spaceAfter=6,
        wordWrap="CJK",
    ),
),
        Spacer(1, 14),
        Paragraph(
            "<b>Disclaimer:</b> This report is generated by a "
            "demonstration phishing-detection system. Predictions and "
            "rule-based indicators can be incorrect. Do not treat this "
            "report alone as proof that an email is safe or malicious.",
            styles["SmallNote"],
        ),
    ])

    document.build(story)

    pdf_buffer.seek(0)

    response = make_response(pdf_buffer.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = (
        'attachment; filename="PhishGuard_Analysis_Report.pdf"'
    )

    return response



@app.route("/clear-history", methods=["POST"])
def clear_history():
    with get_db() as connection:
        connection.execute("DELETE FROM scan_history")

    return redirect(url_for("home"))



if __name__ == "__main__":
    app.run(debug=True)
