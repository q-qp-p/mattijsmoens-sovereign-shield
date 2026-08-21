"""
Ollama provider for VetoShield.

No extra dependencies — uses stdlib requests to localhost.
Fully offline, zero cost.
"""

import json
import urllib.request
import urllib.error

from sovereign_shield.providers.base import LLMProvider
from sovereign_shield.prompts import (
    VERIFICATION_PROMPT,
    STRUCTURED_VERIFICATION_PROMPT,
    VERDICT_CATEGORIES,
    VERDICT_SEVERITIES,
)


class OllamaProvider(LLMProvider):
    """Uses a local Ollama model for attack verification. Zero cost, fully offline."""

    def __init__(
        self,
        model: str = "llama3.1:8b",
        host: str = "http://localhost:11434",
    ):
        self._model = model
        self._host = host.rstrip("/")

    def verify(self, text: str) -> str:
        return self._run(VERIFICATION_PROMPT.format(text=text), num_predict=10)

    def verify_structured(self, text: str) -> str:
        """Ask for a JSON verdict document for multi-model consensus."""
        prompt = STRUCTURED_VERIFICATION_PROMPT.format(
            text=text,
            categories=list(VERDICT_CATEGORIES),
            severities=list(VERDICT_SEVERITIES),
        )
        # Ollama can constrain decoding to JSON natively, which removes most
        # unparseable replies before they reach the schema check.
        return self._run(prompt, num_predict=120, json_format=True)

    def _run(self, prompt: str, num_predict: int = 10, json_format: bool = False) -> str:
        body = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.0,
                "num_predict": num_predict,
            },
        }
        if json_format:
            body["format"] = "json"
        payload = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(
            f"{self._host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response", "").strip()
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Cannot connect to Ollama at {self._host}. "
                f"Is Ollama running? Error: {e}"
            )

    @property
    def name(self) -> str:
        return f"Ollama({self._model})"
