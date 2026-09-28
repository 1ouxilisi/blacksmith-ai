"""
Email Notifications - Send email alerts for high-severity findings.
Supports SMTP with TLS authentication.
"""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
from utils.fp_filter import TriageResult


class EmailNotifier:
    """Send email notifications for important findings."""

    def __init__(self):
        self.smtp_server = os.getenv("SMTP_SERVER", "")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.from_email = os.getenv("FROM_EMAIL", self.smtp_user)
        self.to_email = os.getenv("TO_EMAIL", "")
        self.enabled = bool(self.smtp_server and self.smtp_user and self.to_email)

    def send_email(self, subject: str, body: str, html: bool = False) -> bool:
        """Send an email."""
        if not self.enabled:
            print("[Email] Not configured, skipping")
            return False

        try:
            msg = MIMEMultipart()
            msg["From"] = self.from_email
            msg["To"] = self.to_email
            msg["Subject"] = subject

            if html:
                msg.attach(MIMEText(body, "html"))
            else:
                msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

            print(f"[Email] Sent: {subject}")
            return True

        except Exception as e:
            print(f"[Email] Failed: {e}")
            return False

    def notify_finding(self, result: TriageResult):
        """Send email for a high-severity finding."""
        if result.suggested_severity not in ["critical", "high"]:
            return

        subject = f"[{result.suggested_severity.upper()}] {result.raw_finding.title}"
        body = f"""
New finding discovered:

Target: {result.raw_finding.target}
Type: {result.raw_finding.vuln_type}
Title: {result.raw_finding.title}
Severity: {result.suggested_severity}
Confidence: {result.confidence:.0%}

Reasoning:
{result.reasoning}
"""
        self.send_email(subject, body)

    def notify_hunt_complete(self, stats: dict):
        """Send email when batch hunt completes."""
        subject = "Batch Hunt Complete"
        body = f"""
Batch vulnerability hunting completed.

Targets scanned: {stats.get('completed', 0)}
Findings to review: {stats.get('review_queue', 0)}
False positives filtered: {stats.get('false_positive', 0)}

Check the dashboard for details.
"""
        self.send_email(subject, body)


# Global instance
email_notifier = EmailNotifier()
