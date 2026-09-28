"""
Notification System - Alert on high/critical findings.
Supports webhook (DingTalk/WeChat/Feishu), email, and desktop notifications.
"""
import os
import json
import requests
from typing import Optional
from utils.fp_filter import TriageResult


class Notifier:
    """Send notifications for important findings."""

    def __init__(self):
        self.webhook_url = os.getenv("NOTIFY_WEBHOOK_URL", "")
        self.email_enabled = os.getenv("NOTIFY_EMAIL_ENABLED", "false").lower() == "true"
        self.min_severity = os.getenv("NOTIFY_MIN_SEVERITY", "high")
        self.severity_order = ["info", "low", "medium", "high", "critical"]

    def should_notify(self, severity: str) -> bool:
        """Check if finding severity meets notification threshold."""
        try:
            return self.severity_order.index(severity.lower()) >= self.severity_order.index(self.min_severity)
        except ValueError:
            return False

    def send_webhook(self, title: str, content: str, severity: str = "medium"):
        """Send notification via webhook (DingTalk/Feishu/WeChat Work)."""
        if not self.webhook_url:
            return

        emoji = {"critical": "🚨", "high": "🔴", "medium": "🟡", "low": "🔵", "info": "ℹ️"}.get(severity, "📢")

        payload = {
            "msgtype": "text",
            "text": {
                "content": f"{emoji} [{severity.upper()}] {title}\n\n{content}"
            }
        }

        try:
            requests.post(self.webhook_url, json=payload, timeout=10)
            print(f"[Notifier] Webhook sent: {title}")
        except Exception as e:
            print(f"[Notifier] Webhook failed: {e}")

    def notify_finding(self, result: TriageResult):
        """Notify about a new finding that passed triage."""
        if result.decision.value not in ["confirmed", "likely"]:
            return

        if not self.should_notify(result.suggested_severity):
            return

        title = f"New {result.suggested_severity.upper()} Finding: {result.raw_finding.title}"
        content = f"""Target: {result.raw_finding.target}
Type: {result.raw_finding.vuln_type}
Scanner: {result.raw_finding.scanner}
Confidence: {result.confidence:.0%}
Reasoning: {result.reasoning[:200]}
"""

        self.send_webhook(title, content, result.suggested_severity)

    def notify_hunt_complete(self, stats: dict):
        """Notify when batch hunt completes."""
        title = "Batch Hunt Complete"
        content = f"""Targets scanned: {stats.get('completed', 0)}
Findings to review: {stats.get('review_queue', 0)}
False positives filtered: {stats.get('false_positive', 0)}
"""
        self.send_webhook(title, content, "info")


# Global instance
notifier = Notifier()
