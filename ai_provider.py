"""
AI Provider Module - Universal LLM Support
Supports LiteLLM (100+ LLMs) with fallback to direct Gemini SDK
"""

import os

DEFAULT_MODEL = "gemini-3-flash"

# Try to import litellm, fallback to direct Gemini SDK if not available
try:
    import litellm
    litellm.suppress_debug_info = True
    LITELLM_AVAILABLE = True
except ImportError:
    LITELLM_AVAILABLE = False


class AIProvider:
    """Universal AI Provider - uses LiteLLM if available, else direct Gemini SDK"""
    
    def __init__(self, model: str = None, api_key: str = None, api_base: str = None):
        """
        Initialize AI Provider.
        
        Args:
            model: Model name (e.g., "gemini-3-flash" or "openai/gpt-5.2")
            api_key: API key
            api_base: Custom API base URL (for proxies)
        """
        self.model = model or DEFAULT_MODEL
        self.api_key = api_key
        self.api_base = api_base
        self._client = None
    
    def call(self, prompt: str, temperature: float = 0.7, max_tokens: int = 8192) -> str:
        """Call the LLM with given prompt."""
        if LITELLM_AVAILABLE:
            return self._call_litellm(prompt, temperature, max_tokens)
        else:
            return self._call_gemini_direct(prompt, temperature, max_tokens)
    
    def _call_litellm(self, prompt: str, temperature: float, max_tokens: int) -> str:
        """Call via LiteLLM (supports 100+ models)"""
        try:
            # Add gemini/ prefix if no provider specified
            model = self.model
            if "/" not in model:
                model = f"gemini/{model}"
            
            kwargs = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            
            if self.api_key:
                kwargs["api_key"] = self.api_key
            if self.api_base:
                kwargs["api_base"] = self.api_base
            
            response = litellm.completion(**kwargs)
            return response.choices[0].message.content
            
        except Exception as e:
            return f"Error calling {self.model} via LiteLLM: {e}"
    
    def _call_gemini_direct(self, prompt: str, temperature: float, max_tokens: int) -> str:
        """Direct call to Gemini SDK (fallback when LiteLLM not available)"""
        try:
            from google import genai
            from google.genai import types
            
            if self._client is None:
                self._client = genai.Client(api_key=self.api_key)
            
            # Remove gemini/ prefix if present
            model = self.model
            if model.startswith("gemini/"):
                model = model[7:]
            
            contents = [
                types.Content(
                    role="user",
                    parts=[types.Part.from_text(text=prompt)]
                )
            ]
            
            config = types.GenerateContentConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
            )
            
            response = self._client.models.generate_content(
                model=model,
                contents=contents,
                config=config
            )
            
            # Handle multi-part responses
            if response.candidates and response.candidates[0].content.parts:
                text_parts = []
                for part in response.candidates[0].content.parts:
                    if hasattr(part, 'text') and part.text:
                        text_parts.append(part.text)
                return "\n".join(text_parts)
            
            return response.text
            
        except ImportError:
            return "Error: Neither litellm nor google-genai is installed. Run: pip install google-genai"
        except Exception as e:
            return f"Error calling Gemini: {e}"


# Backwards compatibility alias
GeminiProvider = AIProvider


def get_provider(model: str = None, api_key: str = None, api_base: str = None) -> AIProvider:
    """Factory function to get AI provider."""
    return AIProvider(model=model, api_key=api_key, api_base=api_base)


# =============================================================================
# AI ANALYSIS FUNCTIONS
# =============================================================================

def explain_vulnerability(provider: AIProvider, vuln_title: str, 
                          vuln_cwe: str, code_snippet: str) -> str:
    """Generate AI explanation of a vulnerability."""
    prompt = f"""You are a security researcher analyzing decompiled binary code from IDA Pro.

**Vulnerability Report:**
- Title: {vuln_title}
- CWE: {vuln_cwe}

**Flagged Code:**
```c
{code_snippet}
```

**CRITICAL: First, assess if this is a REAL vulnerability or a FALSE POSITIVE.**

Analyze the code carefully:
- Is the vulnerability actually exploitable in this context?
- Are there any mitigations, bounds checks, or safe usages visible?
- Could this be a safe pattern that just looks similar to a vulnerability?

**Your response MUST start with one of these verdicts:**
- `[CONFIRMED VULNERABILITY]` - if the code is genuinely vulnerable
- `[LIKELY FALSE POSITIVE]` - if this appears to be incorrectly flagged

Then provide:
1. **Verdict Explanation**: Why you classified it this way
2. **Technical Analysis**: Detailed explanation of the code behavior
3. **If CONFIRMED**: Attack vector, impact, and fix recommendation
4. **If FALSE POSITIVE**: Why the static analyzer incorrectly flagged this

Format with markdown. Be precise and technical."""

    return provider.call(prompt, temperature=0.3)


def generate_poc(provider: AIProvider, vuln_title: str,
                 vuln_cwe: str, code_snippet: str, func_name: str) -> str:
    """Generate proof-of-concept exploit for a vulnerability."""
    prompt = f"""You are creating a proof-of-concept exploit for educational purposes.

**Target Vulnerability:**
- Function: {func_name}
- Title: {vuln_title}
- CWE: {vuln_cwe}

**Vulnerable Code:**
```c
{code_snippet}
```

**Instructions:**
1. Create a minimal PoC that demonstrates the vulnerability
2. Show input that would trigger the bug
3. Explain what happens when the PoC runs
4. Include Python/C code if applicable

This is for security research only. Format with markdown code blocks."""

    return provider.call(prompt, temperature=0.5)


def analyze_function(provider: AIProvider, pseudocode: str, func_name: str) -> str:
    """Analyze a function for security issues."""
    prompt = f"""You are a security researcher analyzing decompiled code from IDA Pro.

**Function: {func_name}**

```c
{pseudocode}
```

**Analyze this function for:**
1. Security vulnerabilities (buffer overflows, format strings, injections, etc.)
2. Interesting security-relevant behavior
3. Potential attack vectors
4. Cryptographic operations or sensitive data handling

Provide a detailed security analysis. Format with markdown."""

    return provider.call(prompt, temperature=0.4)
