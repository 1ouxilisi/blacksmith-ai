"""
Ollama Local Model Support - Use local LLM models via Ollama.
Enables fully offline penetration testing without cloud API dependencies.
"""
import os
import requests
from typing import Optional, Dict, Any
from langchain_openai import ChatOpenAI
from dotenv import load_dotenv


class OllamaManager:
    """Manage local LLM models via Ollama."""

    def __init__(self, host: str = "http://localhost:11434"):
        self.host = os.getenv("OLLAMA_HOST", host)
        self.available = self._check_connection()

    def _check_connection(self) -> bool:
        """Check if Ollama is running."""
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def list_models(self) -> list:
        """List available local models."""
        if not self.available:
            return []
        try:
            resp = requests.get(f"{self.host}/api/tags", timeout=10)
            data = resp.json()
            return [m.get("name", "") for m in data.get("models", [])]
        except Exception:
            return []

    def get_model(self, model_name: str = "llama3.2") -> Optional[ChatOpenAI]:
        """Get a LangChain ChatOpenAI instance pointing to Ollama."""
        if not self.available:
            print("[Ollama] Not connected, falling back to cloud API")
            return None

        return ChatOpenAI(
            model=model_name,
            base_url=f"{self.host}/v1",
            api_key="ollama",  # Ollama doesn't need a real key
            max_retries=2,
            temperature=0,
        )

    def pull_model(self, model_name: str) -> bool:
        """Pull a model from Ollama library."""
        try:
            resp = requests.post(
                f"{self.host}/api/pull",
                json={"name": model_name},
                stream=True,
                timeout=300,
            )
            return resp.status_code == 200
        except Exception as e:
            print(f"[Ollama] Pull failed: {e}")
            return False


# Global instance
ollama_manager = OllamaManager()
