"""
User Authentication - Enterprise-grade access control.
Features: login, API keys, role-based access, audit log.
"""
import os
import json
import hashlib
import secrets
from datetime import datetime
from typing import Dict, Any, Optional


class AuthManager:
    """Manage user authentication and authorization."""

    def __init__(self):
        self.users_file = "./store/users.json"
        self.audit_log_file = "./store/audit_log.json"
        self._ensure_files()

    def _ensure_files(self):
        """Ensure data files exist."""
        os.makedirs("./store", exist_ok=True)
        if not os.path.exists(self.users_file):
            with open(self.users_file, "w") as f:
                json.dump({"users": {}}, f)
        if not os.path.exists(self.audit_log_file):
            with open(self.audit_log_file, "w") as f:
                json.dump({"logs": []}, f)

    def _load_users(self) -> Dict:
        with open(self.users_file, "r") as f:
            return json.load(f)

    def _save_users(self, data: Dict):
        with open(self.users_file, "w") as f:
            json.dump(data, f, indent=2)

    def create_user(self, username: str, password: str, role: str = "user") -> Dict[str, Any]:
        """Create a new user."""
        data = self._load_users()

        if username in data["users"]:
            return {"success": False, "error": "User already exists"}

        # Hash password
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()

        # Generate API key
        api_key = f"bs_{secrets.token_hex(32)}"

        data["users"][username] = {
            "password_hash": password_hash,
            "salt": salt,
            "role": role,
            "api_key": api_key,
            "created_at": datetime.now().isoformat(),
            "last_login": None,
        }

        self._save_users(data)
        self._log_action(username, "create_user")

        return {
            "success": True,
            "api_key": api_key,
            "message": f"User {username} created successfully"
        }

    def authenticate(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate user with username and password."""
        data = self._load_users()

        if username not in data["users"]:
            return None

        user = data["users"][username]
        password_hash = hashlib.sha256((password + user["salt"]).encode()).hexdigest()

        if password_hash != user["password_hash"]:
            self._log_action(username, "failed_login")
            return None

        # Update last login
        user["last_login"] = datetime.now().isoformat()
        self._save_users(data)
        self._log_action(username, "login")

        return {
            "username": username,
            "role": user["role"],
            "api_key": user["api_key"],
        }

    def authenticate_api_key(self, api_key: str) -> Optional[Dict]:
        """Authenticate with API key."""
        data = self._load_users()

        for username, user in data["users"].items():
            if user["api_key"] == api_key:
                self._log_action(username, "api_auth")
                return {
                    "username": username,
                    "role": user["role"],
                }

        return None

    def _log_action(self, username: str, action: str):
        """Log user action."""
        with open(self.audit_log_file, "r") as f:
            log_data = json.load(f)

        log_data["logs"].append({
            "username": username,
            "action": action,
            "timestamp": datetime.now().isoformat(),
        })

        # Keep last 1000 logs
        if len(log_data["logs"]) > 1000:
            log_data["logs"] = log_data["logs"][-1000:]

        with open(self.audit_log_file, "w") as f:
            json.dump(log_data, f, indent=2)

    def get_audit_logs(self, limit: int = 100) -> list:
        """Get recent audit logs."""
        with open(self.audit_log_file, "r") as f:
            log_data = json.load(f)
        return log_data["logs"][-limit:]


# Global instance
auth_manager = AuthManager()
