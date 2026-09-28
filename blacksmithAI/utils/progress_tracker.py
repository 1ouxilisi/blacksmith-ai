"""
Scan Progress Tracker - Global scan state for real-time UI updates.
"""
import threading
from typing import Dict, Any
from datetime import datetime


class ScanProgressTracker:
    """Track current scan progress for UI polling."""

    def __init__(self):
        self._lock = threading.Lock()
        self._state = {
            "running": False,
            "target": "",
            "current_step": "",
            "message": "",
            "percent": 0,
            "started_at": None,
            "findings_count": 0,
        }

    def start(self, target: str):
        """Mark scan as started."""
        with self._lock:
            self._state = {
                "running": True,
                "target": target,
                "current_step": "init",
                "message": "Starting scan...",
                "percent": 0,
                "started_at": datetime.now().isoformat(),
                "findings_count": 0,
            }

    def update(self, step: str, message: str, percent: int):
        """Update scan progress."""
        with self._lock:
            self._state["current_step"] = step
            self._state["message"] = message
            self._state["percent"] = percent

    def complete(self, findings_count: int = 0):
        """Mark scan as completed."""
        with self._lock:
            self._state["running"] = False
            self._state["percent"] = 100
            self._state["message"] = "Scan completed"
            self._state["findings_count"] = findings_count

    def get_state(self) -> Dict[str, Any]:
        """Get current state (thread-safe)."""
        with self._lock:
            return dict(self._state)


# Global instance
progress_tracker = ScanProgressTracker()
