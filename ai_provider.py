"""
AI Provider Module - OpenAI Client
Simple wrapper using OpenAI client for calling LLM providers.
"""

import os

DEFAULT_MODEL = "claude-sonnet-4-5"

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    print("[Symbiotic] Warning: openai not installed. Run: pip install openai")


class AIProvider:
    """Universal AI Provider using OpenAI client."""

    def __init__(self, model: str = None, api_key: str = None, api_base: str = None):
        """
        Initialize AI Provider.

        Args:
            model: Model name (e.g., "claude-sonnet-4-5", "claude-haiku-4-5")
            api_key: API key for the provider
            api_base: Custom API base URL (for proxies like Symbiotic)
        """
        self.model = model or DEFAULT_MODEL
        # Remove provider prefix if present (e.g., "openai/claude-sonnet-4.5" -> "claude-sonnet-4.5")
        if "/" in self.model:
            self.model = self.model.split("/", 1)[1]
        self.api_key = api_key
        self.api_base = api_base
        self.client = None

        if OPENAI_AVAILABLE and api_key and api_base:
            self.client = OpenAI(base_url=api_base, api_key=api_key)

    def call(self, prompt: str, temperature: float = 0.7, max_tokens: int = 8192) -> str:
        """Call the LLM with given prompt."""
        if not OPENAI_AVAILABLE:
            return "Error: openai not installed. Run: pip install openai"

        if not self.client:
            return "Error: AI not configured. Check API key and base URL."

        try:
            print(f"[Symbiotic AI] Calling {self.model} (base: {self.api_base or 'default'})")

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return response.choices[0].message.content

        except Exception as e:
            return f"Error calling {self.model}: {e}"


def get_provider(model: str = None, api_key: str = None, api_base: str = None) -> AIProvider:
    """Factory function to get AI provider."""
    return AIProvider(model=model, api_key=api_key, api_base=api_base)
