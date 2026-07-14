"""
Weekly Report Generator for BrandShield.
Sends email digests with threat summaries, DMCA status, and suspicious accounts.
"""
import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Email configuration - set via environment variables on Render
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
FROM_EMAIL = os.getenv("FROM_EMAIL", "legal@byerim.com")
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
RESEND_FROM = os.getenv("RESEND_FROM", "BrandShield <legal@byerim.com>")
REPORT_RECIPIENTS = os.getenv(
    "REPORT_RECIPIENTS", "sat@byerim.com,erim@byerim.com"
).split(",")

# BCC every weekly report to this address for audit trail.
# Set LEGAL_BCC="" on Render to disable.
LEGAL_BCC = os.getenv("LEGAL_BCC", "legal@byerim.com").strip()


def _send_via_resend(to_addresses: list, subject: str, html_body: str, plain_body: str) -> bool:
    """Send email using Resend HTTP API."""
    import requests
    payload = {
        "from": RESEND_FROM,
        "to": to_addresses,
        "subject": subject,
        "html": html_body,
        "text": plain_body,
    }
    # BCC the legal/audit address (skip if it's already in the To list)
    to_lower = {a.strip().lower() for a in to_addresses}
    if LEGAL_BCC and LEGAL_BCC.lower() not in to_lower:
        payload["bcc"] = [LEGAL_BCC]
    resp = requests.post(
        "https://api.resend.com/emails",
        json=payload,
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        timeout=15,
    )
    if resp.status_code in (200, 201):
        logger.info(f"Resend email sent, id={resp.json().get('id')}")
        return True
    else:
        raise Exception(f"Resend API error {resp.status_code}: {resp.text[:300]}")


def _get_weekly_data(days=7):
    """Gather stats for the past `days` days (default 7)."""
    from backend.database import query

    week_ago = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    # New threats this week
    new_threats = query(
        "SELECT * FROM threats WHERE detected_at >= ? ORDER BY severity DESC, confidence DESC",
        (week_ago,),
    )

    # All active (non-resolved, non-ignored) threats
    active_threats = query(
        "SELECT * FROM threats WHERE status NOT IN ('resolved', 'ignored') ORDER BY severity DESC"
    )

    # Ignored threats
    ignored_count_row = query(
        "SELECT COUNT(*) as cnt FROM threats WHERE status = 'ignored'", one=True
    )
    ignored_count = ignored_count_row["cnt"] if ignored_count_row else 0

    # DMCA notices this week
    new_dmca = query(
        "SELECT d.*, t.brand, t.infringer_username, t.platform "
        "FROM dmca_notices d LEFT JOIN threats t ON d.threat_id = t.id "
        "WHERE d.created_at >= ? ORDER BY d.created_at DESC",
        (week_ago,),
    )

    # DMCA status updates (responses received)
    dmca_responses = query(
        "SELECT d.*, t.brand, t.infringer_username "
        "FROM dmca_notices d LEFT JOIN threats t ON d.threat_id = t.id "
        "WHERE d.response_at >= ? ORDER BY d.response_at DESC",
        (week_ago,),
    )

    # Suspicious accounts
    suspects = query(
        "SELECT * FROM suspicious_accounts WHERE status = 'suspected' ORDER BY risk_score DESC"
    )

    # Severity breakdown of active threats
    severity_counts = {}
    for sev in ["critical", "high", "medium", "low"]:
        row = query(
            "SELECT COUNT(*) as cnt FROM threats WHERE severity = ? AND status NOT IN ('resolved', 'ignored')",
            (sev,),
            one=True,
        )
        severity_counts[sev] = row["cnt"] if row else 0

    # Brand breakdown
    brand_counts = {}
    brands = query(
        "SELECT brand, COUNT(*) as cnt FROM threats WHERE status NOT IN ('resolved', 'ignored') GROUP BY brand"
    )
    for b in brands:
        brand_counts[b["brand"]] = b["cnt"]

    # Scan activity
    scans = query(
        "SELECT * FROM scan_history WHERE started_at >= ? ORDER BY started_at DESC",
        (week_ago,),
    )

    return {
        "new_threats": new_threats,
        "active_threats": active_threats,
        "ignored_count": ignored_count,
        "new_dmca": new_dmca,
        "dmca_responses": dmca_responses,
        "suspects": suspects,
        "severity": severity_counts,
        "brands": brand_counts,
        "scans": scans,
        "period_start": week_ago,
        "period_end": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _severity_color(severity):
    """Return hex color for severity level."""
    return {
        "critical": "#f85149",
        "high": "#f0883e",
        "medium": "#d29922",
        "low": "#8b949e",
    }.get(severity, "#8b949e")


def _status_label(status):
    """Pretty-print status."""
    return {
        "new": "New",
        "reported": "Reported",
        "resolved": "Resolved",
        "ignored": "Ignored",
        "sent": "Sent",
        "draft": "Draft",
    }.get(status, status.capitalize() if status else "Unknown")


def build_report_html(data):
    """Build HTML email body for the weekly report."""
    new_count = len(data["new_threats"])
    active_count = len(data["active_threats"])
    ignored_count = data["ignored_count"]
    dmca_count = len(data["new_dmca"])
    suspect_count = len(data["suspects"])
    sev = data["severity"]

    # Header
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
<div style="max-width:640px;margin:0 auto;padding:24px;">

<!-- Header -->
<div style="text-align:center;padding:24px 0;border-bottom:1px solid #21262d;">
    <h1 style="color:#58a6ff;margin:0;font-size:24px;">BrandShield Report</h1>
    <p style="color:#8b949e;margin:8px 0 0;font-size:14px;">
        {datetime.utcnow().strftime('%d %B %Y')} &mdash; Protecting @erim &amp; @byerim
    </p>
</div>

<!-- Summary Cards -->
<div style="display:flex;gap:12px;margin:20px 0;flex-wrap:wrap;">
    <div style="flex:1;min-width:120px;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;text-align:center;">
        <div style="color:#8b949e;font-size:12px;text-transform:uppercase;">New This Week</div>
        <div style="color:#f85149;font-size:28px;font-weight:bold;margin:4px 0;">{new_count}</div>
    </div>
    <div style="flex:1;min-width:120px;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;text-align:center;">
        <div style="color:#8b949e;font-size:12px;text-transform:uppercase;">Active Threats</div>
        <div style="color:#f0883e;font-size:28px;font-weight:bold;margin:4px 0;">{active_count}</div>
    </div>
    <div style="flex:1;min-width:120px;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;text-align:center;">
        <div style="color:#8b949e;font-size:12px;text-transform:uppercase;">DMCA Sent</div>
        <div style="color:#58a6ff;font-size:28px;font-weight:bold;margin:4px 0;">{dmca_count}</div>
    </div>
    <div style="flex:1;min-width:120px;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;text-align:center;">
        <div style="color:#8b949e;font-size:12px;text-transform:uppercase;">Suspects</div>
        <div style="color:#d29922;font-size:28px;font-weight:bold;margin:4px 0;">{suspect_count}</div>
    </div>
</div>

<!-- Severity Breakdown -->
<div style="background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;margin:16px 0;">
    <h3 style="color:#e6edf3;margin:0 0 12px;font-size:14px;">Active Threat Severity</h3>
    <div style="display:flex;gap:16px;flex-wrap:wrap;">
        <span style="color:#f85149;font-weight:bold;">{sev.get('critical',0)} Critical</span>
        <span style="color:#f0883e;font-weight:bold;">{sev.get('high',0)} High</span>
        <span style="color:#d29922;font-weight:bold;">{sev.get('medium',0)} Medium</span>
        <span style="color:#8b949e;font-weight:bold;">{sev.get('low',0)} Low</span>
    </div>
    <div style="color:#8b949e;font-size:12px;margin-top:8px;">{ignored_count} threat(s) marked as ignored</div>
</div>
"""

    # New Threats Table
    if data["new_threats"]:
        html += """
<div style="background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;margin:16px 0;">
    <h3 style="color:#e6edf3;margin:0 0 12px;font-size:14px;">New Threats Detected This Week</h3>
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
    <tr style="border-bottom:1px solid #21262d;">
        <th style="color:#8b949e;text-align:left;padding:8px 4px;">Brand</th>
        <th style="color:#8b949e;text-align:left;padding:8px 4px;">Infringer</th>
        <th style="color:#8b949e;text-align:left;padding:8px 4px;">Platform</th>
        <th style="color:#8b949e;text-align:left;padding:8px 4px;">Type</th>
        <th style="color:#8b949e;text-align:left;padding:8px 4px;">Severity</th>
        <th style="color:#8b949e;text-align:right;padding:8px 4px;">Confidence</th>
    </tr>
"""
        for t in data["new_threats"][:20]:
            sev_color = _severity_color(t.get("severity", "medium"))
            conf = t.get("confidence", 0)
            conf_display = f"{int(conf * 100)}%" if conf <= 1 else f"{int(conf)}%"
            html += f"""
    <tr style="border-bottom:1px solid #21262d;">
        <td style="color:#e6edf3;padding:8px 4px;">{t.get('brand','')}</td>
        <td style="color:#e6edf3;padding:8px 4px;">{t.get('infringer_username','Unknown')}</td>
        <td style="color:#e6edf3;padding:8px 4px;">{t.get('platform','')}</td>
        <td style="color:#e6edf3;padding:8px 4px;">{t.get('threat_type','')}</td>
        <td style="padding:8px 4px;">
            <span style="color:{sev_color};font-weight:bold;">{(t.get('severity','') or '').capitalize()}</span>
        </td>
        <td style="color:#e6edf3;padding:8px 4px;text-align:right;">{conf_display}</td>
    </tr>"""
        html += "</table></div>"

    # Suggested DMCA Actions
    actionable = [
        t for t in data["active_threats"]
        if t.get("status") == "new"
        and t.get("severity") in ("critical", "high")
        and t.get("confidence", 0) >= 0.75
    ]
    if actionable:
        html += """
<div style="background:#161b22;border:1px solid #f0883e;border-radius:8px;padding:16px;margin:16px 0;">
    <h3 style="color:#f0883e;margin:0 0 8px;font-size:14px;">Suggested DMCA Actions</h3>
    <p style="color:#8b949e;font-size:12px;margin:0 0 12px;">These high-confidence threats are recommended for takedown.</p>
"""
        for t in actionable[:10]:
            conf = t.get("confidence", 0)
            conf_display = f"{int(conf * 100)}%" if conf <= 1 else f"{int(conf)}%"
            html += f"""
    <div style="border-bottom:1px solid #21262d;padding:8px 0;">
        <span style="color:#e6edf3;font-weight:bold;">{t.get('infringer_username','')}</span>
        <span style="color:#8b949e;"> on {t.get('platform','')} ({t.get('brand','')}) &mdash; {conf_display} confidence</span>
    </div>"""
        html += "</div>"

    # DMCA Status Updates
    if data["dmca_responses"]:
        html += """
<div style="background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;margin:16px 0;">
    <h3 style="color:#e6edf3;margin:0 0 12px;font-size:14px;">DMCA Responses Received</h3>
"""
        for d_item in data["dmca_responses"]:
            html += f"""
    <div style="border-bottom:1px solid #21262d;padding:8px 0;">
        <span style="color:#e6edf3;">{d_item.get('subject_line','')}</span><br>
        <span style="color:#8b949e;font-size:12px;">
            Status: {_status_label(d_item.get('status',''))} &mdash;
            {d_item.get('response_text','No response text')}
        </span>
    </div>"""
        html += "</div>"

    # Suspicious Accounts
    if data["suspects"]:
        html += """
<div style="background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px;margin:16px 0;">
    <h3 style="color:#e6edf3;margin:0 0 12px;font-size:14px;">Active Suspicious Accounts</h3>
"""
        for s in data["suspects"][:10]:
            risk = s.get("risk_score", 0)
            risk_display = f"{int(risk * 100)}%" if risk <= 1 else f"{int(risk)}%"
            html += f"""
    <div style="border-bottom:1px solid #21262d;padding:8px 0;">
        <span style="color:#e6edf3;font-weight:bold;">@{s.get('username','')}</span>
        <span style="color:#8b949e;"> ({s.get('platform','')}) &mdash; {risk_display} risk &mdash; {s.get('follower_count',0)} followers</span>
    </div>"""
        html += "</div>"

    # Footer with CTA
    html += f"""
<!-- Call to Action -->
<div style="text-align:center;padding:24px 0;margin-top:16px;">
    <a href="https://brand-shield.onrender.com/"
       style="display:inline-block;background:#238636;color:#fff;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:bold;font-size:14px;">
        Open BrandShield Dashboard &rarr;
    </a>
</div>

<!-- Footer -->
<div style="text-align:center;padding:16px 0;border-top:1px solid #21262d;">
    <p style="color:#484f58;font-size:12px;margin:0;">
        BrandShield &mdash; Automated Brand Protection for @erim &amp; @byerim<br>
        This report is generated daily. Log in to action threats or adjust settings.<br>
        <a href="https://brand-shield.onrender.com" style="color:#484f58;">brand-shield.onrender.com</a>
    </p>
</div>

</div>
</body>
</html>"""
    return html


def send_daily_report():
    """Generate and send the DAILY digest email (past 24h)."""
    return _send_report(days=1, label="Daily")


def send_weekly_report():
    """Generate and send the weekly report email (past 7 days)."""
    return _send_report(days=7, label="Weekly")


def _send_report(days=1, label="Daily"):
    """Generate and send a report covering the past `days` days."""
    logger.info(f"Generating {label.lower()} digest...")

    try:
        data = _get_weekly_data(days=days)
        html_body = build_report_html(data)

        new_count = len(data["new_threats"])
        active_count = len(data["active_threats"])
        window = "today" if days == 1 else f"this {label.lower().rstrip('ly') or 'period'}"
        subject = (
            f"BrandShield {label}: {new_count} new, {len(data['new_dmca'])} takedowns sent, "
            f"{active_count} active | {datetime.utcnow().strftime('%d %b %Y')}"
        )

        plain_text = (
            f"BrandShield {label} Digest - {datetime.utcnow().strftime('%d %b %Y')}\n\n"
            f"New threats {window}: {new_count}\n"
            f"Active threats: {active_count}\n"
            f"Takedown notices sent: {len(data['new_dmca'])}\n"
            f"Suspicious accounts: {len(data['suspects'])}\n\n"
            f"View full dashboard: https://brand-shield.onrender.com/"
        )

        # Prefer Resend, fallback to SMTP, or save draft if neither configured
        if RESEND_API_KEY:
            _send_via_resend(REPORT_RECIPIENTS, subject, html_body, plain_text)
            logger.info(f"{label} digest sent via Resend to {REPORT_RECIPIENTS}")
            _save_report_to_db(subject, html_body, data, sent=True)
            return {"sent": True, "method": "resend", "recipients": REPORT_RECIPIENTS, "subject": subject}
        elif SMTP_USER and SMTP_PASS:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = FROM_EMAIL
            msg["To"] = ", ".join(REPORT_RECIPIENTS)
            msg.attach(MIMEText(plain_text, "plain"))
            msg.attach(MIMEText(html_body, "html"))
            # Build envelope recipient list including the legal/audit BCC
            recipients = list(REPORT_RECIPIENTS)
            recipients_lower = {a.strip().lower() for a in recipients}
            if LEGAL_BCC and LEGAL_BCC.lower() not in recipients_lower:
                recipients.append(LEGAL_BCC)

            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(FROM_EMAIL, recipients, msg.as_string())
            logger.info(f"Daily digest sent via SMTP to {REPORT_RECIPIENTS}")
            _save_report_to_db(subject, html_body, data, sent=True)
            return {"sent": True, "method": "smtp", "recipients": REPORT_RECIPIENTS, "subject": subject}
        else:
            logger.warning(
                "No email provider configured (set RESEND_API_KEY or SMTP_USER+SMTP_PASS). "
                "Report generated but not sent."
            )
            _save_report_to_db(subject, html_body, data)
            return {"sent": False, "reason": "No email provider configured", "subject": subject}

    except Exception as e:
        logger.error(f"Failed to send {label.lower()} digest: {e}", exc_info=True)
        return {"sent": False, "error": str(e)}


def _save_report_to_db(subject, html_body, data, sent=False):
    """Save report record to scan_history for tracking."""
    try:
        from backend.database import execute

        execute(
            """INSERT INTO scan_history
               (scan_type, brand, platform, items_scanned, threats_found,
                execution_time_seconds, status, started_at, completed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "weekly_report",
                "all",
                "email",
                len(data["active_threats"]),
                len(data["new_threats"]),
                0,
                "completed" if sent else "draft",
                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
    except Exception as e:
        logger.warning(f"Could not save report to DB: {e}")


def get_latest_report_html():
    """Generate the report HTML for dashboard preview (no email send)."""
    data = _get_weekly_data()
    return build_report_html(data)
