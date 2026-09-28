"""
Billing System - Production-grade tier management.
Free / Pro / Enterprise tiers.
"""
import os
import json
from datetime import datetime
from typing import Dict, Any


class BillingSystem:
    """Manage user tiers and billing."""

    def __init__(self):
        self.tiers_file = "./store/tiers.json"
        self._ensure_file()

        # Tier definitions
        self.tier_definitions = {
            "free": {
                "name": "Free",
                "price": 0,
                "limits": {
                    "scans_per_month": 10,
                    "targets": 1,
                    "report_formats": ["html"],
                    "api_access": False,
                    "priority_support": False,
                },
                "features": [
                    "Basic LLM security scanning",
                    "OWASP LLM Top 10",
                    "HTML reports",
                    "Community support",
                ]
            },
            "pro": {
                "name": "Pro",
                "price": 49,
                "limits": {
                    "scans_per_month": 100,
                    "targets": 10,
                    "report_formats": ["html", "json", "pdf"],
                    "api_access": True,
                    "priority_support": True,
                },
                "features": [
                    "Everything in Free",
                    "All 78 test categories",
                    "Auto attack generation",
                    "False positive filtering",
                    "JSON/PDF reports",
                    "API access",
                    "Priority email support",
                ]
            },
            "enterprise": {
                "name": "Enterprise",
                "price": 499,
                "limits": {
                    "scans_per_month": -1,  # unlimited
                    "targets": -1,  # unlimited
                    "report_formats": ["html", "json", "pdf", "excel"],
                    "api_access": True,
                    "priority_support": True,
                    "sso_integration": True,
                    "dedicated_support": True,
                },
                "features": [
                    "Everything in Pro",
                    "Unlimited scans",
                    "SSO integration",
                    "Dedicated support",
                    "Custom integrations",
                    "SLA guarantee",
                ]
            }
        }

    def _ensure_file(self):
        os.makedirs("./store", exist_ok=True)
        if not os.path.exists(self.tiers_file):
            with open(self.tiers_file, "w") as f:
                json.dump({"users": {}}, f)

    def get_user_tier(self, username: str) -> Dict[str, Any]:
        """Get user's current tier."""
        with open(self.tiers_file, "r") as f:
            data = json.load(f)

        user_tier = data["users"].get(username, "free")
        tier_info = self.tier_definitions[user_tier].copy()
        tier_info["tier"] = user_tier

        # Add usage stats
        usage = data.get("usage", {}).get(username, {})
        tier_info["usage"] = usage

        return tier_info

    def upgrade_tier(self, username: str, new_tier: str) -> Dict[str, Any]:
        """Upgrade user to a new tier."""
        if new_tier not in self.tier_definitions:
            return {"success": False, "error": "Invalid tier"}

        with open(self.tiers_file, "r") as f:
            data = json.load(f)

        data["users"][username] = new_tier
        data.setdefault("usage", {}).setdefault(username, {
            "scans_this_month": 0,
            "last_upgrade": datetime.now().isoformat(),
        })

        with open(self.tiers_file, "w") as f:
            json.dump(data, f, indent=2)

        return {
            "success": True,
            "message": f"Upgraded to {new_tier}",
            "price": self.tier_definitions[new_tier]["price"],
        }

    def check_quota(self, username: str, action: str) -> Dict[str, Any]:
        """Check if user has quota for an action."""
        tier_info = self.get_user_tier(username)
        limits = tier_info["limits"]

        if action == "scan":
            scans_used = tier_info["usage"].get("scans_this_month", 0)
            scans_limit = limits.get("scans_per_month", 10)

            if scans_limit == -1:  # unlimited
                return {"allowed": True, "remaining": "unlimited"}

            remaining = scans_limit - scans_used
            return {
                "allowed": remaining > 0,
                "remaining": remaining,
                "limit": scans_limit,
                "used": scans_used,
            }

        return {"allowed": True}

    def record_scan(self, username: str):
        """Record a scan usage."""
        with open(self.tiers_file, "r") as f:
            data = json.load(f)

        usage = data.setdefault("usage", {}).setdefault(username, {})
        usage["scans_this_month"] = usage.get("scans_this_month", 0) + 1
        usage["last_scan"] = datetime.now().isoformat()

        with open(self.tiers_file, "w") as f:
            json.dump(data, f, indent=2)


# Global instance
billing = BillingSystem()
