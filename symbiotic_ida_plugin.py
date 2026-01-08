"""
IDA Security Scanner Plugin
Scans decompiled pseudocode for security vulnerabilities using opengrep-core.
Features AI analysis for explanations, PoC generation, and function analysis.
"""

import os
import sys

import idaapi
import ida_hexrays
import ida_kernwin
import ida_funcs
import idc

PLUGIN_DIR = os.path.dirname(__file__)
PARENT_DIR = os.path.dirname(PLUGIN_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from config import SymbioticConfig, configure_symbiotic
from scanner import SymbioticScanner
from viewer import SymbioticResultsViewer

# Load version from ida-plugin.json
import json
try:
    with open(os.path.join(PLUGIN_DIR, "ida-plugin.json"), "r") as f:
        VERSION = json.load(f).get("plugin", {}).get("version", "0.0.1")
except:
    VERSION = "0.1.2"


class ScanCurrentFunctionAction(ida_kernwin.action_handler_t):
    """Action handler for scanning current function"""
    
    def __init__(self, plugin):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        self.plugin.scan_current_function(ea)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class ScanAllFunctionsAction(ida_kernwin.action_handler_t):
    """Action handler for scanning all functions"""
    
    def __init__(self, plugin):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.scan_all_functions()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class ConfigureAction(ida_kernwin.action_handler_t):
    """Action handler for configuration"""
    
    def __init__(self, plugin):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        configure_symbiotic(self.plugin.config)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class AskAIAction(ida_kernwin.action_handler_t):
    """Action handler for Ask AI about current function"""
    
    def __init__(self, plugin):
        ida_kernwin.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        self.plugin.ask_ai_about_function()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class SymbioticPlugin(idaapi.plugin_t):
    """Main IDA Plugin class"""
    
    flags = idaapi.PLUGIN_KEEP
    comment = "Symbiotic Security Scanner - Scan code for vulnerabilities"
    help = "Use Ctrl+Shift+S to scan current function, Ctrl+Shift+L to scan all"
    wanted_name = "Symbiotic"
    wanted_hotkey = ""

    def init(self):
        """Initialize the plugin"""
        print(f"\n[Symbiotic] Security Scanner v{VERSION} loading...")
        
        self.config = SymbioticConfig()
        self.scanner = SymbioticScanner(self.config)
        self._scanning = False

        # Check for decompiler
        if not ida_hexrays.init_hexrays_plugin():
            print("[Symbiotic] Warning: Hex-Rays decompiler not available")

        # Print status
        print(f"[Symbiotic] Opengrep: {self.config.opengrep_path}")
        print(f"[Symbiotic] Rules: {self.config.rules_path}")
        ai_status = "[OK]" if self.config.is_ai_configured() else "[X] Not set"
        print(f"[Symbiotic] Gemini AI: {ai_status}")
        status = "[OK] Configured" if self.config.is_configured() else "[X] Not configured"
        print(f"[Symbiotic] Status: {status}")

        # Register actions
        self._register_actions()

        print(f"[Symbiotic] v{VERSION} loaded successfully!")
        print("[Symbiotic] Shortcuts: Ctrl+Shift+S (scan), Ctrl+Shift+L (scan all), Ctrl+Shift+A (ask AI)")
        
        return idaapi.PLUGIN_KEEP

    def _register_actions(self):
        """Register all plugin actions"""
        # Scan Current Function
        action_desc = ida_kernwin.action_desc_t(
            "symbiotic:scan_current",
            "Symbiotic: Scan Current Function",
            ScanCurrentFunctionAction(self),
            "Ctrl+Shift+S",
            "Scan the current function for vulnerabilities",
            -1
        )
        ida_kernwin.register_action(action_desc)
        ida_kernwin.attach_action_to_menu("Edit/Plugins/", "symbiotic:scan_current", ida_kernwin.SETMENU_APP)

        # Scan All Functions
        action_desc = ida_kernwin.action_desc_t(
            "symbiotic:scan_all",
            "Symbiotic: Scan ALL Functions",
            ScanAllFunctionsAction(self),
            "Ctrl+Shift+L",
            "Scan all functions in the binary",
            -1
        )
        ida_kernwin.register_action(action_desc)
        ida_kernwin.attach_action_to_menu("Edit/Plugins/", "symbiotic:scan_all", ida_kernwin.SETMENU_APP)

        # Configuration
        action_desc = ida_kernwin.action_desc_t(
            "symbiotic:configure",
            "Symbiotic: Configuration",
            ConfigureAction(self),
            "",
            "Configure Symbiotic Scanner",
            -1
        )
        ida_kernwin.register_action(action_desc)
        ida_kernwin.attach_action_to_menu("Edit/Plugins/", "symbiotic:configure", ida_kernwin.SETMENU_APP)

        # Ask AI about function
        action_desc = ida_kernwin.action_desc_t(
            "symbiotic:ask_ai",
            "Symbiotic: Ask AI About Function",
            AskAIAction(self),
            "Ctrl+Shift+A",
            "Ask AI to analyze the current function",
            -1
        )
        ida_kernwin.register_action(action_desc)
        ida_kernwin.attach_action_to_menu("Edit/Plugins/", "symbiotic:ask_ai", ida_kernwin.SETMENU_APP)


    def run(self, arg):
        """Run plugin - Show dialog with options"""
        msg = f"""Symbiotic Security Scanner v{VERSION}

Choose an action:"""

        result = ida_kernwin.ask_buttons(
            "Scan Current Function",
            "Scan ALL Functions",
            "Configuration",
            ida_kernwin.ASKBTN_BTN2,
            msg
        )

        if result == ida_kernwin.ASKBTN_BTN1:
            if not self.config.is_configured():
                ida_kernwin.warning("Please configure Symbiotic Scanner first!")
                configure_symbiotic(self.config)
            else:
                ea = ida_kernwin.get_screen_ea()
                self.scan_current_function(ea)

        elif result == ida_kernwin.ASKBTN_BTN2:
            if not self.config.is_configured():
                ida_kernwin.warning("Please configure Symbiotic Scanner first!")
                configure_symbiotic(self.config)
            else:
                self.scan_all_functions()

        elif result == ida_kernwin.ASKBTN_BTN3:
            configure_symbiotic(self.config)

    def scan_current_function(self, ea):
        """Scan function at current address (async)"""
        func = ida_funcs.get_func(ea)
        if not func:
            ida_kernwin.warning("No function at current address")
            return

        if self._scanning:
            ida_kernwin.warning("A scan is already in progress")
            return

        func_name = idc.get_func_name(ea)
        print(f"\n[Symbiotic] Starting async scan of: {func_name}")
        
        self._scanning = True
        ida_kernwin.show_wait_box(f"Scanning {func_name}...")

        def on_complete(result):
            self._scanning = False
            ida_kernwin.hide_wait_box()
            
            if "error" in result:
                print(f"[Symbiotic] Scan failed: {result['error']}")
            else:
                print("[Symbiotic] Scan completed!")
            
            viewer = SymbioticResultsViewer(result)
            viewer.Show("Symbiotic Scan Results")

        self.scanner.scan_function_async(func.start_ea, on_complete)

    def scan_all_functions(self):
        """Scan all functions (async)"""
        if self._scanning:
            ida_kernwin.warning("A scan is already in progress")
            return

        print("\n[Symbiotic] Starting async scan of all functions...")
        
        self._scanning = True
        ida_kernwin.show_wait_box("Scanning all functions...")

        def on_complete(result):
            self._scanning = False
            ida_kernwin.hide_wait_box()
            
            if "error" in result:
                print(f"[Symbiotic] Scan failed: {result['error']}")
            else:
                print("[Symbiotic] Scan completed!")
            
            viewer = SymbioticResultsViewer(result)
            viewer.Show("Symbiotic Scan Results")

        self.scanner.scan_all_functions_async(on_complete)

    def ask_ai_about_function(self):
        """Ask AI to analyze the current function"""
        from ai_provider import AIProvider
        from ai_prompts import analyze_function
        
        if not self.config.is_ai_configured():
            ida_kernwin.warning("AI not configured!\n\nAdd AI_MODEL and AI_API_KEY to .env file")
            return
        
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if not func:
            ida_kernwin.warning("No function at current address")
            return
        
        func_name = idc.get_func_name(ea)
        print(f"[Symbiotic] Asking AI to analyze: {func_name}")
        
        # Get pseudocode
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                ida_kernwin.warning("Failed to decompile function")
                return
            pseudocode = str(cfunc)
        except Exception as e:
            ida_kernwin.warning(f"Decompilation failed: {e}")
            return
        
        ida_kernwin.show_wait_box(f"Analyzing {func_name} with AI...")
        
        try:
            provider = AIProvider(
                model=self.config.ai_model, 
                api_key=self.config.ai_api_key,
                api_base=self.config.ai_api_base
            )
            analysis = analyze_function(provider, pseudocode, func_name)
            ida_kernwin.hide_wait_box()
            
            # Show result
            msg = f"AI Analysis of {func_name}\n{'='*50}\n\n{analysis}"
            if len(msg) > 2000:
                print(f"\n[Symbiotic AI] Analysis:\n{analysis}\n")
                ida_kernwin.info(msg[:2000] + "\n\n... (see Output window for full)")
            else:
                print(f"\n[Symbiotic AI] Analysis:\n{analysis}\n")
                ida_kernwin.info(msg)
                
        except Exception as e:
            ida_kernwin.hide_wait_box()
            ida_kernwin.warning(f"AI Error: {e}")


    def term(self):
        """Terminate the plugin"""
        ida_kernwin.unregister_action("symbiotic:scan_current")
        ida_kernwin.unregister_action("symbiotic:scan_all")
        ida_kernwin.unregister_action("symbiotic:configure")
        ida_kernwin.unregister_action("symbiotic:ask_ai")

        print("[Symbiotic] Plugin unloaded")


def PLUGIN_ENTRY():
    return SymbioticPlugin()
