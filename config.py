"""
Configuration Module
Manages opengrep-core and AI configuration for IDA plugin
"""

import os
import json

# Configuration file paths
PLUGIN_DIR = os.path.dirname(os.path.dirname(__file__))
CONFIG_FILE = os.path.join(PLUGIN_DIR, "symbiotic_config.json")
ENV_FILE = os.path.join(PLUGIN_DIR, ".env")


def load_env_file(env_path):
    """Load variables from .env file"""
    env_vars = {}
    if os.path.exists(env_path):
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        env_vars[key.strip()] = value.strip()
        except Exception as e:
            print(f"[Symbiotic] Failed to load .env: {e}")
    return env_vars


class SymbioticConfig:
    """Manage opengrep and AI configuration"""

    def __init__(self):
        self.opengrep_path = os.path.join(PLUGIN_DIR, "opengrep-core")
        self.rules_path = os.path.join(PLUGIN_DIR, "code-rules.yaml")
        # AI Configuration
        self.gemini_api_key = ""
        self.gemini_model = "gemini-3-flash"
        self.load()

    def load(self):
        """Load configuration from .env and JSON file"""
        # First load from .env file
        env_vars = load_env_file(ENV_FILE)
        if env_vars:
            self.gemini_api_key = env_vars.get("GEMINI_API_KEY", "")
            self.gemini_model = env_vars.get("GEMINI_MODEL", "gemini-3-flash")
        
        # Then load from JSON config (can override)
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r") as f:
                    data = json.load(f)
                    self.opengrep_path = data.get("opengrep_path", self.opengrep_path)
                    self.rules_path = data.get("rules_path", self.rules_path)
                    # Only override if set in JSON
                    if data.get("gemini_api_key"):
                        self.gemini_api_key = data.get("gemini_api_key")
                    if data.get("gemini_model"):
                        self.gemini_model = data.get("gemini_model")
        except Exception as e:
            print(f"[Symbiotic] Failed to load config: {e}")

    def save(self):
        """Save configuration to file"""
        try:
            data = {
                "opengrep_path": self.opengrep_path,
                "rules_path": self.rules_path,
                "gemini_api_key": self.gemini_api_key,
                "gemini_model": self.gemini_model
            }
            with open(CONFIG_FILE, "w") as f:
                json.dump(data, f, indent=2)
            print("[Symbiotic] Configuration saved")
        except Exception as e:
            print(f"[Symbiotic] Failed to save config: {e}")

    def is_configured(self):
        """Check if configuration is complete"""
        return bool(self.opengrep_path and os.path.exists(self.opengrep_path))
    
    def is_ai_configured(self):
        """Check if AI (Gemini) is configured"""
        return bool(self.gemini_api_key)

    def get_status_string(self):
        """Return configuration status string"""
        opengrep_exists = "[OK]" if self.opengrep_path and os.path.exists(self.opengrep_path) else "[X]"
        rules_exists = "[OK]" if self.rules_path and os.path.exists(self.rules_path) else "[X]"
        ai_status = "[OK]" if self.is_ai_configured() else "[X]"
        api_key_display = self.gemini_api_key[:10] + "..." if self.gemini_api_key else "(not set)"
        status = "[OK] Configured" if self.is_configured() else "[X] Not configured"
        
        return f"""Scanner Configuration:
  Opengrep Path: {self.opengrep_path or '(not set)'}
  Rules Path:    {self.rules_path or '(not set)'}
  Opengrep:      {opengrep_exists}
  Rules:         {rules_exists}
  
AI Configuration:
  Gemini API:    {api_key_display}
  Model:         {self.gemini_model}
  AI Features:   {ai_status}
  
Status: {status}"""


def configure_symbiotic(config):
    """Configuration dialog using IDA dialogs"""
    import ida_kernwin
    
    def show_main_menu():
        return f"""Symbiotic Configuration
{'='*40}
{config.get_status_string()}
{'='*40}

What would you like to configure?"""

    while True:
        result = ida_kernwin.ask_buttons(
            "Scanner", 
            "AI (Gemini)", 
            "Done", 
            1, 
            show_main_menu()
        )
        
        if result == 1:  # Scanner config
            configure_scanner(config)
        elif result == 2:  # AI config
            configure_ai(config)
        elif result == 0 or result == -1:  # Done
            config.save()
            break

    return config.is_configured()


def configure_scanner(config):
    """Scanner configuration submenu"""
    import ida_kernwin
    
    while True:
        menu = f"""Scanner Configuration
{'='*40}
Opengrep: {config.opengrep_path or '(not set)'}
Rules:    {config.rules_path or '(not set)'}
{'='*40}"""
        
        result = ida_kernwin.ask_buttons("Opengrep Path", "Rules Path", "Back", 1, menu)
        
        if result == 1:
            new_path = ida_kernwin.ask_file(0, config.opengrep_path or "", "Select opengrep-core binary")
            if new_path:
                config.opengrep_path = new_path
        elif result == 2:
            new_path = ida_kernwin.ask_file(0, config.rules_path or "", "Select rules YAML file")
            if new_path:
                config.rules_path = new_path
        else:
            break


def configure_ai(config):
    """AI/Gemini configuration submenu"""
    import ida_kernwin
    
    MODELS = [
        "gemini-3-flash-preview",
        "gemini-3-pro-preview",
    ]
    
    while True:
        api_display = config.gemini_api_key[:15] + "..." if config.gemini_api_key else "(not set)"
        menu = f"""AI Configuration (Gemini)
{'='*40}
API Key: {api_display}
Model:   {config.gemini_model}
Status:  {'[OK] Configured' if config.is_ai_configured() else '[X] Not configured'}
{'='*40}

Get API key at: makersuite.google.com/app/apikey"""
        
        result = ida_kernwin.ask_buttons("Set API Key", "Change Model", "Back", 1, menu)
        
        if result == 1:  # Set API Key
            new_key = ida_kernwin.ask_str(
                config.gemini_api_key or "",
                0,
                "Enter Gemini API Key (starts with AIza):"
            )
            if new_key:
                config.gemini_api_key = new_key
                print(f"[Symbiotic] Gemini API key set")
                
        elif result == 2:  # Change Model
            # Simple model selection
            model_menu = "Select Gemini Model:\n\n"
            for i, m in enumerate(MODELS, 1):
                current = " (current)" if m == config.gemini_model else ""
                model_menu += f"{i}. {m}{current}\n"
            
            choice = ida_kernwin.ask_long(1, model_menu)
            if choice and 1 <= choice <= len(MODELS):
                config.gemini_model = MODELS[choice - 1]
                print(f"[Symbiotic] Model set to {config.gemini_model}")
        else:
            break

