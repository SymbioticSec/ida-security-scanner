"""
Configuration Module
Manages opengrep-core and AI configuration for IDA plugin
"""

import os

# Configuration file paths
# PLUGIN_DIR = where this plugin lives (symbiotic folder)
# PLUGINS_DIR = IDA plugins folder (parent, where .env goes)
PLUGIN_DIR = os.path.dirname(__file__)
PLUGINS_DIR = os.path.dirname(PLUGIN_DIR)
ENV_FILE = os.path.join(PLUGINS_DIR, ".env")


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
    else:
        print(f"[Symbiotic] Warning: .env not found at {env_path}")
    return env_vars


class SymbioticConfig:
    """Manage opengrep and AI configuration"""

    def __init__(self):
        self.opengrep_path = os.path.join(PLUGINS_DIR, "opengrep-core")
        rules_in_plugin = os.path.join(PLUGIN_DIR, "code-rules.yaml")
        rules_in_plugins = os.path.join(PLUGINS_DIR, "code-rules.yaml")
        self.rules_path = rules_in_plugin if os.path.exists(rules_in_plugin) else rules_in_plugins

        self.ai_model = "gemini/gemini-3-flash"
        self.ai_api_key = ""
        self.ai_api_base = ""

        self.load()

    def load(self):
        """Load configuration from .env file"""
        env_vars = load_env_file(ENV_FILE)
        if env_vars:
            self.ai_model = env_vars.get("AI_MODEL", "gemini/gemini-3-flash")
            self.ai_api_key = env_vars.get("AI_API_KEY", "")
            self.ai_api_base = env_vars.get("AI_API_BASE", "")
            
            print(f"[Symbiotic] Config loaded: model={self.ai_model}, api_base={self.ai_api_base or '(none)'}")

    def is_configured(self):
        """Check if scanner is configured"""
        return bool(self.opengrep_path and os.path.exists(self.opengrep_path))
    
    def is_ai_configured(self):
        """Check if AI is configured"""
        return bool(self.ai_api_key)

    def get_status_string(self):
        """Return configuration status string"""
        opengrep_exists = "[OK]" if self.opengrep_path and os.path.exists(self.opengrep_path) else "[X]"
        rules_exists = "[OK]" if self.rules_path and os.path.exists(self.rules_path) else "[X]"
        ai_status = "[OK]" if self.is_ai_configured() else "[X]"
        api_key_display = self.ai_api_key[:10] + "..." if self.ai_api_key else "(not set)"
        api_base_display = self.ai_api_base if self.ai_api_base else "(direct)"
        status = "[OK] Configured" if self.is_configured() else "[X] Not configured"
        
        return f"""Scanner Configuration:
  Opengrep Path: {self.opengrep_path or '(not set)'}
  Rules Path:    {self.rules_path or '(not set)'}
  Opengrep:      {opengrep_exists}
  Rules:         {rules_exists}
  
AI Configuration:
  Model:         {self.ai_model}
  API Key:       {api_key_display}
  API Base:      {api_base_display}
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

Configure scanner paths below.
AI is configured via .env file."""

    while True:
        result = ida_kernwin.ask_buttons(
            "Scanner", 
            "Done", 
            "", 
            1, 
            show_main_menu()
        )
        
        if result == 1:
            configure_scanner(config)
        else:
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
