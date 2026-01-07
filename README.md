# IDA Security Scanner

<p align="center">
  <img src="https://img.shields.io/badge/IDA%20Pro-9.0%2B-blue?style=for-the-badge" alt="IDA Pro 9.2+"/>
  <img src="https://img.shields.io/badge/Python-3.10%2B-green?style=for-the-badge" alt="Python 3.10+"/>
</p>

A security-focused code scanner for IDA Pro that combines **IDA's decompilation capabilities with SAST (Static Application Security Testing) rules**. This approach leverages the power of IDA's decompiler to analyze binaries and applies static analysis patterns directly on the pseudocode output.

## Why This Approach?

Traditional binary analysis requires manual inspection of decompiled code. This plugin takes a different approach:

1. **Export pseudocode** from IDA's decompiler
2. **Run SAST rules** using [opengrep](https://github.com/opengrep/opengrep) on the C-like output
3. **Display results** with an interactive UI inside IDA

This can save significant time during vulnerability research, CTF challenges, or security audits by automatically highlighting dangerous patterns.

## Features

- **Automatic Vulnerability Detection** - Scans decompiled functions for dangerous patterns
- **YAML-based Rules** - Easy to customize and extend
- **Interactive UI** - Filter by severity, function, add custom tags
- **AI Analysis** (Optional) - Get explanations via LLM integration
- **Persistent State** - Tags survive between sessions

## Installation

1. **Copy the folder** to IDA plugins:
   ```bash
   # macOS
   cp -r ida-security-scanner /Applications/IDA*/Contents/MacOS/plugins/

   # Windows
   xcopy ida-security-scanner %IDADIR%\plugins\ida-security-scanner\ /E /I

   # Linux
   cp -r ida-security-scanner ~/.idapro/plugins/
   ```

2. **Download opengrep** from [releases](https://github.com/opengrep/opengrep/releases) and place in the plugin folder

3. **Configure AI** (optional):
   ```bash
   cp .env.example .env
   # Edit .env with your API key
   ```

## Usage

| Shortcut | Action |
|----------|--------|
| `Ctrl+Shift+S` | Scan current function |
| `Ctrl+Shift+L` | Scan ALL functions |
| `Ctrl+Shift+A` | Ask AI about function |

## AI System

The plugin uses the **OpenAI Python client** to call LLM APIs for vulnerability analysis.

### Supported Providers

| Provider | Direct Support | Endpoint |
|----------|----------------|----------|
| **OpenAI** | Yes | `https://api.openai.com/v1` |
| **Anthropic** | Yes | `https://api.anthropic.com/v1` |
| **Google Gemini** | Via proxy only | Requires OpenAI-compatible proxy |

### Configuration

Copy `.env.example` to your IDA plugins folder and edit it:

```bash
cp .env.example /path/to/IDA/plugins/.env
```

See `.env.example` for all options and available models.

## Detection Rules

Edit `code-rules.yaml` to add your own patterns:

```yaml
rules:
- id: BUFFER_OVERFLOW
  languages: [c]
  message: "Dangerous gets() call - buffer overflow"
  pattern: gets($BUF)
  severity: CRITICAL
```

See [opengrep documentation](https://github.com/opengrep/opengrep) for pattern syntax.

## Example Rules Included

The default `code-rules.yaml` includes detection for:

- `gets()` - Guaranteed buffer overflow
- `scanf("%s")` - Unbounded input
- Format string attacks (`printf(argv[N])`)
- Command injection patterns (`strcat` + `system`)
- Privilege escalation (`setuid` + `system`)
- Backdoor patterns (`execve("/bin/sh")`)

## Project Structure

```
ida-security-scanner/
├── symbiotic_ida_plugin.py    # Entry point
├── scanner.py                 # Opengrep integration
├── viewer.py                  # UI components
├── ai_provider.py             # LLM support (optional)
├── code-rules.yaml            # Detection rules
└── .env.example               # Config template
```

## Credits

- [opengrep](https://github.com/opengrep/opengrep) - Static analysis engine
- [IDA Pro](https://hex-rays.com/) - Reverse engineering platform

## License

MIT License
