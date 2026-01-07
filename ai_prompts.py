"""
AI Prompts Module
Security analysis prompts for LLM-based vulnerability analysis.
"""

from .ai_provider import AIProvider


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
