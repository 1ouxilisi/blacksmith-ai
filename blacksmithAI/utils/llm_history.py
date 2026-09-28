"""
LLM Security Test History - Track all LLM security tests over time.
"""
import os
import json
from datetime import datetime
from typing import List, Dict, Any


class LLMSecurityHistory:
    """Track LLM security test history."""

    def __init__(self):
        self.history_dir = "./outputs/llm_security"
        os.makedirs(self.history_dir, exist_ok=True)

    def save_test(self, target: str, findings: List[Any], summary: Dict[str, Any]):
        """Save a test result to history."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"test_{timestamp}.json"
        filepath = os.path.join(self.history_dir, filename)

        data = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "summary": summary,
            "findings": [
                {
                    "owasp_id": f.owasp_id,
                    "name": f.name,
                    "severity": f.severity,
                    "payload": f.payload,
                }
                for f in findings
            ]
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return filepath

    def get_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent test history."""
        files = sorted(
            [f for f in os.listdir(self.history_dir) if f.endswith(".json")],
            reverse=True
        )[:limit]

        history = []
        for filename in files:
            filepath = os.path.join(self.history_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    history.append(data)
            except Exception:
                pass

        return history

    def get_trend(self) -> Dict[str, Any]:
        """Get security trend over time."""
        history = self.get_history(limit=10)

        if len(history) < 2:
            return {"trend": "not_enough_data", "history": len(history)}

        # Compare latest vs previous
        latest = history[0]
        previous = history[1]

        latest_critical = latest["summary"]["by_severity"]["critical"]
        prev_critical = previous["summary"]["by_severity"]["critical"]

        if latest_critical < prev_critical:
            trend = "improving"
        elif latest_critical > prev_critical:
            trend = "worsening"
        else:
            trend = "stable"

        return {
            "trend": trend,
            "latest_critical": latest_critical,
            "previous_critical": prev_critical,
            "tests": len(history),
        }


# Global instance
llm_history = LLMSecurityHistory()
