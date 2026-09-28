"""
Monitoring - Production-grade performance monitoring and alerting.
"""
import os
import json
import time
from datetime import datetime
from typing import Dict, Any, List


class Monitoring:
    """Monitor performance and generate alerts."""

    def __init__(self):
        self.metrics_file = "./store/metrics.json"
        self.alerts_file = "./store/alerts.json"
        self._ensure_files()

    def _ensure_files(self):
        os.makedirs("./store", exist_ok=True)
        if not os.path.exists(self.metrics_file):
            with open(self.metrics_file, "w") as f:
                json.dump({"metrics": []}, f)
        if not os.path.exists(self.alerts_file):
            with open(self.alerts_file, "w") as f:
                json.dump({"alerts": []}, f)

    def record_scan(self, target: str, duration: float, findings: int, status: str = "completed"):
        """Record a scan metric."""
        metric = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "duration_seconds": duration,
            "findings_count": findings,
            "status": status,
        }

        with open(self.metrics_file, "r") as f:
            data = json.load(f)

        data["metrics"].append(metric)

        # Keep last 1000 metrics
        if len(data["metrics"]) > 1000:
            data["metrics"] = data["metrics"][-1000:]

        with open(self.metrics_file, "w") as f:
            json.dump(data, f, indent=2)

        # Check for alerts
        self._check_alerts(metric)

    def _check_alerts(self, metric: Dict[str, Any]):
        """Check if metric triggers an alert."""
        alerts = []

        # Alert: scan took too long
        if metric["duration_seconds"] > 60:
            alerts.append({
                "type": "slow_scan",
                "severity": "warning",
                "message": f"Scan took {metric['duration_seconds']:.1f}s (> 60s)",
                "timestamp": datetime.now().isoformat(),
            })

        # Alert: too many findings (possible false positive)
        if metric["findings_count"] > 50:
            alerts.append({
                "type": "high_findings",
                "severity": "info",
                "message": f"Scan found {metric['findings_count']} findings (possible false positives)",
                "timestamp": datetime.now().isoformat(),
            })

        # Alert: scan failed
        if metric["status"] == "failed":
            alerts.append({
                "type": "scan_failed",
                "severity": "critical",
                "message": f"Scan failed for {metric['target']}",
                "timestamp": datetime.now().isoformat(),
            })

        if alerts:
            with open(self.alerts_file, "r") as f:
                data = json.load(f)

            data["alerts"].extend(alerts)

            # Keep last 100 alerts
            if len(data["alerts"]) > 100:
                data["alerts"] = data["alerts"][-100:]

            with open(self.alerts_file, "w") as f:
                json.dump(data, f, indent=2)

    def get_metrics(self, limit: int = 50) -> List[Dict]:
        """Get recent metrics."""
        with open(self.metrics_file, "r") as f:
            data = json.load(f)
        return data["metrics"][-limit:]

    def get_alerts(self, limit: int = 20) -> List[Dict]:
        """Get recent alerts."""
        with open(self.alerts_file, "r") as f:
            data = json.load(f)
        return data["alerts"][-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        with open(self.metrics_file, "r") as f:
            data = json.load(f)

        metrics = data["metrics"]
        if not metrics:
            return {"total_scans": 0}

        durations = [m["duration_seconds"] for m in metrics]
        findings = [m["findings_count"] for m in metrics]

        return {
            "total_scans": len(metrics),
            "avg_duration": sum(durations) / len(durations),
            "avg_findings": sum(findings) / len(findings),
            "max_duration": max(durations),
            "max_findings": max(findings),
        }


# Global instance
monitoring = Monitoring()
