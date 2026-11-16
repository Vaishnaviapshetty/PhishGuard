
from pathlib import Path
import os
import re
import sqlite3
import ipaddress
from io import BytesIO
from urllib.parse import urlparse
from xml.sax.saxutils import escape as xml_escape

import joblib
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    make_response,
    session,
)

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishguard_model.joblib"
DATABASE_PATH = BASE_DIR / "phishguard_history.db"

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "FLASK_SECRET_KEY",
    "local-development-secret-change-before-deployment"
)

app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        "Model not found. Run train_model.py first."
    )

model = joblib.load(MODEL_PATH)


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

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


# --------------------------------------------------
# EMAIL SECURITY INDICATORS
# --------------------------------------------------

def analyze_indicators(email_text):
    indicators = []

    urls = re.findall(
        r"""https?://[^\s<>"']+|www\.[^\s<>"']+""",
        email_text,
        flags=re.IGNORECASE,
    )

    # Remove duplicate URLs before counting
    unique_urls = []
    seen_urls = set()

    for url in urls:
        cleaned_url = url.rstrip(".,;:!?)]}")

        if cleaned_url.lower() not in seen_urls:
            seen_urls.add(cleaned_url.lower())
            unique_urls.append(url)

    urls = unique_urls

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
        "goo.gl",
        "ow.ly",
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

# --------------------------------------------------
# URL THREAT ANALYSIS AND RISK SCORING
# --------------------------------------------------

def analyze_url_threats(email_text):

    url_pattern = r"""https?://[^\s<>"']+|www\.[^\s<>"']+"""
    urls = re.findall(url_pattern, email_text, re.IGNORECASE)

    # Remove duplicate URLs while preserving their original order
    unique_urls = []
    seen_urls = set()

    for url in urls:
        cleaned_url = url.rstrip(".,;:!?)]}")

        if cleaned_url.lower() not in seen_urls:
            seen_urls.add(cleaned_url.lower())
            unique_urls.append(url)

    urls = unique_urls

    url_results = []

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "goo.gl",
        "ow.ly",
    ]

    lookalike_patterns = {
        "paypa1": "PayPal",
        "g00gle": "Google",
        "amaz0n": "Amazon",
        "micros0ft": "Microsoft",
    }

    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "account-update",
        "password-reset",
    ]

    risk_weights = {
        "Uses HTTP instead of HTTPS": 15,
        "Uses an IP address instead of a domain": 25,
        "Contains an @ symbol in the URL": 30,
        "Uses a URL shortening service": 20,
        "Contains an unusually deep subdomain structure": 15,
        "Uses an unusual port": 15,
        "Contains an invalid port number": 20,
        "Contains a malformed URL or invalid hostname": 20,
        "Contains a malformed URL or missing hostname": 20,
        "Possible": 35,
        "Contains suspicious URL keyword(s)": 15,
    }

    for url in urls:

        findings = []

        cleaned_url = url.rstrip(".,;:!?)]}")
        check_url = cleaned_url

        if check_url.lower().startswith("www."):
            check_url = "http://" + check_url

        try:
            parsed = urlparse(check_url)

        except ValueError:
            findings.append("Contains a malformed URL or invalid hostname")

            risk_score = risk_weights[
                "Contains a malformed URL or invalid hostname"
            ]

            url_results.append({
                "url": check_url,
                "findings": findings,
                "risk_score": risk_score,
                "risk_level": "LOW"
            })

            continue
        hostname = parsed.hostname or ""

        if not hostname:
            findings.append(
                "Contains a malformed URL or missing hostname"
            )

        # Basic lookalike-domain detection
        for pattern, brand in lookalike_patterns.items():

            if pattern in hostname.lower():
                findings.append(
                    f"Possible {brand} impersonation: "
                    "lookalike text found in domain"
                )

        # Suspicious URL keyword detection
        found_keywords = [
            keyword
            for keyword in suspicious_keywords
            if keyword in cleaned_url.lower()
        ]

        if found_keywords:
            findings.append(
                "Contains suspicious URL keyword(s): "
                + ", ".join(found_keywords)
            )

        # HTTP instead of HTTPS
        if parsed.scheme == "http":
            findings.append("Uses HTTP instead of HTTPS")

        # IP address detection
        is_ip_address = False

        if hostname:
            try:
                ipaddress.ip_address(hostname)
                is_ip_address = True
                findings.append(
                    "Uses an IP address instead of a domain"
                )
            except ValueError:
                pass

        # @ symbol detection
        if "@" in parsed.netloc:
            findings.append(
                "Contains an @ symbol in the URL"
            )

        # URL shortening detection
        if any(
            hostname.lower() == domain
            or hostname.lower().endswith("." + domain)
            for domain in shorteners
        ):
            findings.append(
                "Uses a URL shortening service"
            )

        # Deep subdomain detection
        if hostname.count(".") >= 3 and not is_ip_address:
            findings.append(
                "Contains an unusually deep subdomain structure"
            )

        # Unusual port detection
        try:
            port = parsed.port

            expected_port = 80 if parsed.scheme.lower() == "http" else 443

            if port and port != expected_port:
                findings.append(f"Uses an unusual port: {port}")

        except ValueError:
            findings.append("Contains an invalid port number")

        # Calculate rule-based URL risk score
        risk_score = 0

        for finding in findings:
            for indicator, weight in risk_weights.items():

                if indicator in finding:
                    risk_score += weight
                    break

        risk_score = min(risk_score, 100)

        # Assign URL risk level
        if risk_score >= 75:
            risk_level = "CRITICAL"

        elif risk_score >= 50:
            risk_level = "HIGH"

        elif risk_score >= 25:
            risk_level = "MEDIUM"

        else:
            risk_level = "LOW"

        if not findings:
            findings.append(
                "No basic URL warning signs detected"
            )

        # Store URL analysis results
        url_results.append({
            "url": cleaned_url,
            "findings": findings,
            "risk_score": risk_score,
            "risk_level": risk_level,
        })

    return url_results


# --------------------------------------------------
# HOMEPAGE AND DASHBOARD
# --------------------------------------------------


@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        email_text = request.form.get("email_text", "").strip()

        if len(email_text) > 5000:
            return (
                "Email text is too long. "
                "Please limit it to 5,000 characters.",
                400,
            )

        if not email_text:
            return redirect(url_for("home"))

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
        url_results = analyze_url_threats(email_text)
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

        session["latest_analysis"] = {
            "result": result,
            "phishing_score": phishing_score,
            "indicators": indicators,
            "url_results": url_results,
        }

        return redirect(url_for("home"))

    analysis = session.get("latest_analysis", {})

    result = analysis.get("result")
    phishing_score = analysis.get("phishing_score")
    email_text = ""
    indicators = analysis.get("indicators", [])
    url_results = analysis.get("url_results", [])

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
        url_results=url_results,
        total_scans=total_scans,
        phishing_count=phishing_count,
        legitimate_count=legitimate_count,
        recent_scans=recent_scans,
    )



# --------------------------------------------------
# HTML REPORT DOWNLOAD
# --------------------------------------------------

@app.route("/download-report", methods=["POST"])
def download_report():

    from html import escape
    from datetime import datetime

    email_text = request.form.get(
        "email_text", ""
    ).strip()

    if len(email_text) > 5000:
        return (
            "Email text is too long. "
            "Please limit it to 5,000 characters.",
            400,
        )

    if not email_text:
        return redirect(url_for("home"))

    # Run machine-learning model
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
    url_results = analyze_url_threats(email_text)

    scan_time = datetime.now().astimezone().strftime(
        "%d %B %Y, %I:%M:%S %p %Z"
    )

    # Escape user-supplied content
    safe_email = escape(email_text)
    safe_result = escape(result)

    safe_indicators = "".join(
        f"<li>{escape(indicator)}</li>"
        for indicator in indicators
    )

    # Prepare URL analysis results
    safe_url_results = ""

    if url_results:

        for item in url_results:

            safe_url = escape(item["url"])
            safe_score = item["risk_score"]
            safe_level = escape(item["risk_level"])

            safe_findings = "".join(
                f"<li>{escape(finding)}</li>"
                for finding in item["findings"]
            )

            safe_url_results += f"""
                <div class="url-item">
                    <p><strong>URL:</strong> {safe_url}</p>
                    <p><strong>Rule-based URL risk score:</strong>
                    {safe_score}/100 ({safe_level})</p>
                    <ul>{safe_findings}</ul>
                </div>
            """

    else:
        safe_url_results = (
            "<p>No URLs were detected in this email.</p>"
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

        .url-item {{
            background: #f5f7fa;
            padding: 12px;
            margin-bottom: 12px;
            border-radius: 6px;
            overflow-wrap: anywhere;
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

    <h3>URL Threat Analysis</h3>
    {safe_url_results}

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

    response.headers["Content-Type"] = (
        "text/html; charset=utf-8"
    )

    response.headers["Content-Disposition"] = (
        'attachment; filename="PhishGuard_Analysis_Report.html"'
    )

    return response


# --------------------------------------------------
# PDF REPORT DOWNLOAD
# --------------------------------------------------

@app.route("/download-pdf", methods=["POST"])
def download_pdf():

    from datetime import datetime

    email_text = request.form.get(
        "email_text", ""
    ).strip()
   

    if len(email_text) > 5000:
        return (
            "Email text is too long. "
            "Please limit it to 5,000 characters.",
            400,
        )

    if not email_text:
        return redirect(url_for("home"))

    # Run machine-learning model
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
    url_results = analyze_url_threats(email_text)

    scan_time = datetime.now().astimezone().strftime(
        "%d %B %Y, %I:%M:%S %p %Z"
    )

    # PDF libraries
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import (
        getSampleStyleSheet,
        ParagraphStyle,
    )
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
        Paragraph(
            "Email Security Analysis Report",
            styles["Heading2"],
        ),
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
                f"<b>Phishing probability score:</b> "
                f"{phishing_score}%",
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
        Paragraph(
            "Security Warning Indicators",
            styles["Heading2"],
        ),
    ])

    for indicator in indicators:

        story.append(Paragraph(
            "&#8226; " + xml_escape(indicator),
            styles["BodyText"],
        ))

        story.append(Spacer(1, 4))

    # URL Threat Analysis
    story.extend([
        Spacer(1, 10),
        Paragraph(
            "URL Threat Analysis",
            styles["Heading2"],
        ),
    ])

    if url_results:

        for item in url_results:

            story.append(Paragraph(
                "<b>URL:</b> " + xml_escape(item["url"]),
                styles["BodyText"],
            ))

            story.append(Paragraph(
                "<b>Rule-based URL risk score:</b> "
                f"{item['risk_score']}/100 "
                f"({xml_escape(item['risk_level'])})",
                styles["BodyText"],
            ))

            for finding in item["findings"]:

                story.append(Paragraph(
                    "&#8226; " + xml_escape(finding),
                    styles["BodyText"],
                ))

            story.append(Spacer(1, 8))

    else:

        story.append(Paragraph(
            "No URLs were detected in this email.",
            styles["BodyText"],
        ))

    # Analysed Email
    story.extend([
        Spacer(1, 10),
        Paragraph(
            "Analysed Email",
            styles["Heading2"],
        ),
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

    # Generate the actual PDF
    document.build(story)

    pdf_buffer.seek(0)
    pdf_data = pdf_buffer.getvalue()



    if not pdf_data:
        return "PDF generation failed. Empty PDF data.", 500

    response = make_response(pdf_data)

    response.headers["Content-Type"] = "application/pdf"

    response.headers["Content-Disposition"] = (
        'attachment; filename="PhishGuard_Analysis_Report.pdf"'
    )

    return response


# --------------------------------------------------
# APPLICATION START
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)
