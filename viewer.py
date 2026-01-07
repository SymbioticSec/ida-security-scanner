"""
Results Viewer Module
HTML-based viewer with navigation, export, filtering for IDA
"""

import json
import os
import datetime
import idaapi
import idc
import ida_kernwin

try:
    from PySide6.QtWidgets import (QVBoxLayout, QHBoxLayout, QTextBrowser, 
                                    QPushButton, QComboBox, QLabel, QFileDialog, QWidget)
    from PySide6.QtCore import Qt, QUrl
except ImportError:
    try:
        from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QTextBrowser,
                                      QPushButton, QComboBox, QLabel, QFileDialog, QWidget)
        from PyQt6.QtCore import Qt, QUrl
    except ImportError:
        try:
            from PyQt5.QtWidgets import (QVBoxLayout, QHBoxLayout, QTextBrowser,
                                          QPushButton, QComboBox, QLabel, QFileDialog, QWidget)
            from PyQt5.QtCore import Qt, QUrl
        except ImportError:
            from PySide2.QtWidgets import (QVBoxLayout, QHBoxLayout, QTextBrowser,
                                            QPushButton, QComboBox, QLabel, QFileDialog, QWidget)
            from PySide2.QtCore import Qt, QUrl


# Global scan history
_scan_history = []


class SymbioticResultsViewer(idaapi.PluginForm):
    """HTML-based viewer for displaying scan results with advanced features"""

    def __init__(self, results, func_line_map=None):
        super().__init__()
        self.results = results
        self.func_line_map = func_line_map or results.get("func_line_map", {})
        self.current_filter = "ALL"
        self.current_func_filter = "ALL"
        self.current_tag_filter = "ALL"
        self.vulns = []
        self.ai_results = {}
        self.vuln_tags = {}

        self._load_tags()
        self._load_ai_cache()

        _scan_history.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "results": results,
            "vuln_count": len(self._parse_vulnerabilities())
        })

    def OnCreate(self, form):
        """Called when the form is created"""
        self.parent = self.FormToPyQtWidget(form)

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(8, 8, 8, 8)
        
        # Filter dropdown
        filter_label = QLabel("Severity:")
        filter_label.setStyleSheet("color: #cccccc; padding-right: 5px;")
        toolbar.addWidget(filter_label)
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.filter_combo.setStyleSheet("""
            QComboBox {
                background-color: #3c3c3c;
                color: #cccccc;
                border: 1px solid #555555;
                padding: 4px 8px;
                min-width: 80px;
            }
        """)
        self.filter_combo.currentTextChanged.connect(self._on_filter_changed)
        toolbar.addWidget(self.filter_combo)
        
        # Function filter
        func_label = QLabel("Function:")
        func_label.setStyleSheet("color: #cccccc; padding-left: 10px; padding-right: 5px;")
        toolbar.addWidget(func_label)
        
        self.func_filter_combo = QComboBox()
        self.func_filter_combo.setStyleSheet("""
            QComboBox {
                background-color: #3c3c3c;
                color: #cccccc;
                border: 1px solid #555555;
                padding: 4px 8px;
                min-width: 120px;
            }
        """)
        self.func_filter_combo.currentTextChanged.connect(self._on_func_filter_changed)
        toolbar.addWidget(self.func_filter_combo)
        
        # Tag filter
        tag_label = QLabel("Tag:")
        tag_label.setStyleSheet("color: #cccccc; padding-left: 10px; padding-right: 5px;")
        toolbar.addWidget(tag_label)
        
        self.tag_filter_combo = QComboBox()
        self.tag_filter_combo.addItems(["ALL", "Untagged", "Confirmed", "False Positive"])
        self.tag_filter_combo.setStyleSheet("""
            QComboBox {
                background-color: #3c3c3c;
                color: #cccccc;
                border: 1px solid #555555;
                padding: 4px 8px;
                min-width: 100px;
            }
        """)
        self.tag_filter_combo.currentTextChanged.connect(self._on_tag_filter_changed)
        toolbar.addWidget(self.tag_filter_combo)
        
        toolbar.addStretch()
        
        # Export button
        export_btn = QPushButton("Export JSON")
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #0e639c;
                color: white;
                border: none;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #1177bb;
            }
        """)
        export_btn.clicked.connect(self._export_json)
        toolbar.addWidget(export_btn)
        
        # Export HTML button
        export_html_btn = QPushButton("Export HTML")
        export_html_btn.setStyleSheet("""
            QPushButton {
                background-color: #0e639c;
                color: white;
                border: none;
                padding: 6px 12px;
                margin-left: 5px;
            }
            QPushButton:hover {
                background-color: #1177bb;
            }
        """)
        export_html_btn.clicked.connect(self._export_html)
        toolbar.addWidget(export_html_btn)
        
        # History button
        history_btn = QPushButton(f"History ({len(_scan_history)})")
        history_btn.setStyleSheet("""
            QPushButton {
                background-color: #3c3c3c;
                color: #cccccc;
                border: 1px solid #555555;
                padding: 6px 12px;
                margin-left: 5px;
            }
            QPushButton:hover {
                background-color: #4c4c4c;
            }
        """)
        history_btn.clicked.connect(self._show_history)
        toolbar.addWidget(history_btn)

        toolbar_widget = QWidget()
        toolbar_widget.setLayout(toolbar)
        toolbar_widget.setStyleSheet("background-color: #252526;")
        main_layout.addWidget(toolbar_widget)

        # Browser
        self.browser = QTextBrowser()
        self.browser.setOpenLinks(False)  # Prevent default navigation
        self.browser.setOpenExternalLinks(False)
        self.browser.anchorClicked.connect(self._on_link_clicked)
        self.vulns = self._parse_vulnerabilities()
        self._populate_func_filter()  # Populate function filter dropdown
        self.browser.setHtml(self._generate_html())

        self.browser.setStyleSheet("""
            QTextBrowser {
                background-color: #1e1e1e;
                color: #cccccc;
                border: 0px;
                padding: 0px;
                margin: 0px;
            }
        """)

        main_layout.addWidget(self.browser)
        self.parent.setLayout(main_layout)
        
        self._print_console_summary()

    def _refresh_html(self):
        """Refresh HTML content while preserving scroll position"""
        # Save scroll position
        scrollbar = self.browser.verticalScrollBar()
        scroll_pos = scrollbar.value() if scrollbar else 0
        
        # Update content
        self.browser.setHtml(self._generate_html())
        
        # Restore scroll position after a short delay (Qt needs time to render)
        if scrollbar and scroll_pos > 0:
            try:
                from PySide6.QtCore import QTimer
            except ImportError:
                try:
                    from PyQt6.QtCore import QTimer
                except ImportError:
                    try:
                        from PyQt5.QtCore import QTimer
                    except ImportError:
                        from PySide2.QtCore import QTimer
            
            def restore_scroll():
                scrollbar.setValue(scroll_pos)
            
            QTimer.singleShot(50, restore_scroll)

    def _on_filter_changed(self, severity):
        """Filter vulnerabilities by severity"""
        self.current_filter = severity
        self._refresh_html()

    def _on_func_filter_changed(self, func_name):
        """Filter vulnerabilities by function"""
        self.current_func_filter = func_name
        self._refresh_html()

    def _on_tag_filter_changed(self, tag):
        """Filter vulnerabilities by tag"""
        self.current_tag_filter = tag
        self._refresh_html()

    def _get_tags_file(self):
        """Get path to persistent tags file"""
        idb_path = idc.get_idb_path() if hasattr(idc, 'get_idb_path') else ""
        if idb_path:
            return idb_path + ".symbiotic_tags.json"
        return os.path.expanduser("~/.symbiotic_tags.json")

    def _load_tags(self):
        """Load tags from persistent file"""
        try:
            tags_file = self._get_tags_file()
            if os.path.exists(tags_file):
                with open(tags_file, "r") as f:
                    self.vuln_tags = json.load(f)
        except:
            self.vuln_tags = {}

    def _save_tags(self):
        """Save tags to persistent file"""
        try:
            tags_file = self._get_tags_file()
            with open(tags_file, "w") as f:
                json.dump(self.vuln_tags, f, indent=2)
        except Exception as e:
            print(f"[Symbiotic] Error saving tags: {e}")

    def _get_ai_cache_file(self):
        """Get path to persistent AI cache file"""
        idb_path = idc.get_idb_path() if hasattr(idc, 'get_idb_path') else ""
        if idb_path:
            return idb_path + ".symbiotic_ai_cache.json"
        return os.path.expanduser("~/.symbiotic_ai_cache.json")

    def _load_ai_cache(self):
        """Load AI results from persistent cache"""
        try:
            cache_file = self._get_ai_cache_file()
            if os.path.exists(cache_file):
                with open(cache_file, "r") as f:
                    self.ai_results = json.load(f)
                print(f"[Symbiotic] Loaded {len(self.ai_results)} cached AI results")
        except Exception as e:
            print(f"[Symbiotic] Could not load AI cache: {e}")
            self.ai_results = {}

    def _save_ai_cache(self):
        """Save AI results to persistent cache"""
        try:
            cache_file = self._get_ai_cache_file()
            # Only save completed results (not loading states)
            to_save = {}
            for key, result in self.ai_results.items():
                content = result.get("content", "")
                if not content.startswith("Generating") and not content.startswith("Error"):
                    to_save[key] = result
            
            with open(cache_file, "w") as f:
                json.dump(to_save, f, indent=2)
        except Exception as e:
            print(f"[Symbiotic] Error saving AI cache: {e}")

    def _handle_tag(self, vuln_id, tag_type):
        """Handle tagging a vulnerability"""
        # Don't convert underscores - use ID as-is from URL
        current = self.vuln_tags.get(vuln_id)
        
        # Toggle: if same tag, remove it; otherwise set it
        if current == tag_type:
            del self.vuln_tags[vuln_id]
            print(f"[Symbiotic] Removed tag from {vuln_id}")
        else:
            self.vuln_tags[vuln_id] = tag_type
            print(f"[Symbiotic] Tagged {vuln_id} as {tag_type.upper()}")
        
        self._save_tags()
        self._refresh_html()

    def _populate_func_filter(self):
        """Populate function filter dropdown with unique functions"""
        functions = set(["ALL"])
        for v in self.vulns:
            loc = v.get("location", {})
            line = loc.get("start_line", 0)
            if line:
                _, func_name = self._get_func_info_for_line(line)
                if func_name:
                    functions.add(func_name)
        
        # Update dropdown
        self.func_filter_combo.blockSignals(True)
        self.func_filter_combo.clear()
        self.func_filter_combo.addItems(sorted(functions))
        self.func_filter_combo.blockSignals(False)

    def _on_link_clicked(self, url):
        """Handle internal links - navigate to function or AI actions"""
        url_str = url.toString()
        
        if url_str.startswith("ida://"):
            # Extract address from ida://0x12345
            addr_str = url_str.replace("ida://", "")
            try:
                addr = int(addr_str, 16)
                # Jump to address in IDA
                idc.jumpto(addr)
                print(f"[Symbiotic] Jumped to {hex(addr)}")
            except:
                print(f"[Symbiotic] Invalid address: {addr_str}")
                
        elif url_str.startswith("ai://explain/"):
            # AI Explain vulnerability
            vuln_id = url_str.replace("ai://explain/", "").replace("_", " ")
            self._handle_ai_explain(vuln_id)
            
        elif url_str.startswith("ai://poc/"):
            # AI Generate PoC
            vuln_id = url_str.replace("ai://poc/", "").replace("_", " ")
            self._handle_ai_poc(vuln_id)
            
        elif url_str.startswith("ai://toggle/"):
            # Toggle (hide) AI result
            parts = url_str.replace("ai://toggle/", "").split("/")
            if len(parts) == 2:
                vuln_id = parts[0].replace("_", " ")
                result_type = parts[1]
                self._handle_ai_toggle(vuln_id, result_type)
        
        elif url_str.startswith("tag://confirmed/"):
            vuln_id = url_str.replace("tag://confirmed/", "")
            self._handle_tag(vuln_id, "confirmed")
        
        elif url_str.startswith("tag://false_positive/"):
            vuln_id = url_str.replace("tag://false_positive/", "")
            self._handle_tag(vuln_id, "false_positive")
            
        elif url_str.startswith("http"):
            # Open external link
            import webbrowser
            webbrowser.open(url_str)

    def _handle_ai_explain(self, vuln_id):
        """Call AI to explain a vulnerability (async)"""
        import threading
        from .config import SymbioticConfig
        
        config = SymbioticConfig()
        if not config.is_ai_configured():
            ida_kernwin.warning("Gemini API not configured!\n\nGo to: Edit > Plugins > Symbiotic Configuration > AI")
            return
        
        vuln = self._find_vuln_by_id(vuln_id)
        if not vuln:
            ida_kernwin.warning(f"Vulnerability not found: {vuln_id}")
            return
        
        print(f"[Symbiotic] Calling AI to explain: {vuln.get('title', vuln_id)}")
        
        # Mark as loading - use composite key
        storage_key = f"{vuln_id}_explain"
        self.ai_results[storage_key] = {"type": "explain", "content": "Generating explanation..."}
        self._refresh_html()
        
        def do_ai_call():
            try:
                from .ai_provider import AIProvider
                from .ai_prompts import explain_vulnerability
                provider = AIProvider(model=config.ai_model, api_key=config.ai_api_key, api_base=config.ai_api_base)
                explanation = explain_vulnerability(
                    provider,
                    vuln.get("title", "Vulnerability"),
                    vuln.get("cwe", ""),
                    vuln.get("snippet", "")
                )
                
                # Update on main thread via execute_sync
                def update_ui():
                    self.ai_results[storage_key] = {"type": "explain", "content": explanation}
                    
                    # Check if AI detected this as a false positive
                    if "[LIKELY FALSE POSITIVE]" in explanation.upper() or "LIKELY FALSE POSITIVE" in explanation.upper():
                        # Auto-tag as false positive
                        self.vuln_tags[vuln_id] = "false_positive"
                        self._save_tags()
                        print(f"[Symbiotic AI] Auto-tagged as FALSE POSITIVE: {vuln_id}")
                    elif "[CONFIRMED VULNERABILITY]" in explanation.upper() or "CONFIRMED VULNERABILITY" in explanation.upper():
                        # Auto-tag as confirmed
                        self.vuln_tags[vuln_id] = "confirmed"
                        self._save_tags()
                        print(f"[Symbiotic AI] Auto-tagged as CONFIRMED: {vuln_id}")
                    self._save_ai_cache()  # Persist cache
                    self._refresh_html()
                    print(f"[Symbiotic AI] Explanation generated")
                
                idaapi.execute_sync(update_ui, idaapi.MFF_FAST)
                
            except Exception as e:
                def show_error():
                    self.ai_results[storage_key] = {"type": "explain", "content": f"Error: {e}"}
                    self._refresh_html()
                idaapi.execute_sync(show_error, idaapi.MFF_FAST)
        
        thread = threading.Thread(target=do_ai_call, daemon=True)
        thread.start()

    def _handle_ai_poc(self, vuln_id):
        """Call AI to generate PoC (async)"""
        import threading
        from .config import SymbioticConfig
        
        config = SymbioticConfig()
        if not config.is_ai_configured():
            ida_kernwin.warning("Gemini API not configured!\n\nGo to: Edit > Plugins > Symbiotic Configuration > AI")
            return
        
        vuln = self._find_vuln_by_id(vuln_id)
        if not vuln:
            ida_kernwin.warning(f"Vulnerability not found: {vuln_id}")
            return
        
        print(f"[Symbiotic] Generating PoC for: {vuln.get('title', vuln_id)}")
        
        # Mark as loading - use composite key
        storage_key = f"{vuln_id}_poc"
        self.ai_results[storage_key] = {"type": "poc", "content": "Generating PoC exploit..."}
        self._refresh_html()
        
        def do_ai_call():
            try:
                from .ai_provider import AIProvider
                from .ai_prompts import generate_poc
                provider = AIProvider(model=config.ai_model, api_key=config.ai_api_key, api_base=config.ai_api_base)
                poc = generate_poc(
                    provider,
                    vuln.get("title", "Vulnerability"),
                    vuln.get("cwe", ""),
                    vuln.get("snippet", ""),
                    "target_function"
                )
                
                def update_ui():
                    self.ai_results[storage_key] = {"type": "poc", "content": poc}
                    self._save_ai_cache()  # Persist cache
                    self._refresh_html()
                    print(f"[Symbiotic AI] PoC generated")
                
                idaapi.execute_sync(update_ui, idaapi.MFF_FAST)
                
            except Exception as e:
                def show_error():
                    self.ai_results[storage_key] = {"type": "poc", "content": f"Error: {e}"}
                    self._refresh_html()
                idaapi.execute_sync(show_error, idaapi.MFF_FAST)
        
        thread = threading.Thread(target=do_ai_call, daemon=True)
        thread.start()

    def _handle_ai_toggle(self, vuln_id, result_type):
        """Toggle (collapse/expand) AI result content"""
        # Find the result and toggle its hidden state
        for vid in [vuln_id, vuln_id.replace(" ", "_"), vuln_id.replace("_", " ")]:
            key = f"{vid}_{result_type}"
            if key in self.ai_results:
                result = self.ai_results[key]
                # Toggle hidden state
                result["hidden"] = not result.get("hidden", False)
                print(f"[Symbiotic] Toggled {result_type}: hidden={result['hidden']}")
                break
        
        # Refresh display
        self._refresh_html()

    def _find_vuln_by_id(self, vuln_id):
        """Find vulnerability by rule_id"""
        for v in self.vulns:
            rule_id = v.get("rule_id", "")
            # Match with both spaces and underscores
            if rule_id.replace(" ", "_") == vuln_id.replace(" ", "_"):
                return v
        return None

    def _get_ai_result(self, vuln_id, result_type=None):
        """Get cached AI result for a vulnerability
        
        Args:
            vuln_id: Vulnerability ID (will try with spaces and underscores)
            result_type: 'explain' or 'poc' - required for new composite key lookup
        """
        if not result_type:
            return None
            
        # Normalize vuln_id formats
        vuln_id_spaces = vuln_id.replace("_", " ")
        vuln_id_underscores = vuln_id.replace(" ", "_")
        
        # Try composite keys with both formats
        for vid in [vuln_id, vuln_id_spaces, vuln_id_underscores]:
            key = f"{vid}_{result_type}"
            result = self.ai_results.get(key)
            if result:
                return result
        
        return None
    
    def _render_ai_content(self, result, accent_color):
        """Render AI result content to HTML"""
        content = result.get("content", "")
        
        # Only show loading for actual loading messages (short strings starting with "Generating")
        if content.startswith("Generating") and len(content) < 50:
            return f'<font size="2" color="#a0aec0">{self._escape_html(content)}</font>'
        
        return self._markdown_to_html(content, accent_color)

    def _highlight_code(self, code, lang="c"):
        """Apply syntax highlighting to code with proper formatting"""
        import re
        
        # Colors for syntax highlighting
        colors = {
            "keyword": "#c45d97",    # Pink - keywords
            "type": "#74c1cf",        # Cyan - types
            "string": "#6ad9a9",      # Green - strings
            "comment": "#666666",     # Gray - comments
            "number": "#e5c166",      # Yellow - numbers
            "default": "#e0e0e0",     # White - default
        }
        
        # C/C++ keywords and types
        c_keywords = {'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break', 'continue',
                      'return', 'goto', 'typedef', 'struct', 'union', 'enum', 'sizeof', 'void',
                      'const', 'static', 'extern', 'volatile', 'register', 'inline', 'auto', 
                      'default', 'include', 'define', 'ifdef', 'ifndef', 'endif', 'elif', 'pragma'}
        c_types = {'int', 'char', 'float', 'double', 'long', 'short', 'unsigned', 'signed',
                   'size_t', 'bool', 'NULL', 'true', 'false', 'uint8_t', 'uint16_t', 'uint32_t',
                   'uint64_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t', 'FILE', 'void'}
        
        # Python keywords
        py_keywords = {'def', 'class', 'if', 'elif', 'else', 'for', 'while', 'try', 'except',
                       'finally', 'with', 'as', 'import', 'from', 'return', 'yield', 'raise',
                       'pass', 'break', 'continue', 'and', 'or', 'not', 'in', 'is', 'None',
                       'True', 'False', 'lambda', 'global', 'nonlocal', 'assert', 'async', 'await'}
        
        keywords = py_keywords if lang in ['python', 'py'] else c_keywords
        types = set() if lang in ['python', 'py'] else c_types
        
        def highlight_line(line):
            """Highlight a single line of code"""
            if not line:
                return ""
            
            # Handle leading whitespace (preserve indentation)
            leading_spaces = len(line) - len(line.lstrip(' '))
            indent = '&nbsp;' * leading_spaces
            line = line[leading_spaces:]
            
            # Check for C-style comments
            if line.strip().startswith('//'):
                return f'{indent}<font color="{colors["comment"]}">{self._escape_html(line)}</font>'
            
            # Check for Python comments
            if lang in ['python', 'py'] and line.strip().startswith('#'):
                return f'{indent}<font color="{colors["comment"]}">{self._escape_html(line)}</font>'
            
            # Tokenize and highlight
            result = [indent]
            
            # Split by word boundaries but keep delimiters
            tokens = re.split(r'(\s+|[^\w]+)', line)
            
            in_string = False
            string_char = None
            
            for token in tokens:
                if not token:
                    continue
                
                # Handle strings
                if not in_string and (token.startswith('"') or token.startswith("'")):
                    in_string = True
                    string_char = token[0]
                    result.append(f'<font color="{colors["string"]}">{self._escape_html(token)}')
                    if len(token) > 1 and token.endswith(string_char):
                        in_string = False
                        result.append('</font>')
                    continue
                
                if in_string:
                    result.append(self._escape_html(token))
                    if token.endswith(string_char) and not token.endswith('\\' + string_char):
                        in_string = False
                        result.append('</font>')
                    continue
                
                escaped = self._escape_html(token)
                
                # Highlight based on token type
                if token in keywords:
                    result.append(f'<font color="{colors["keyword"]}">{escaped}</font>')
                elif token in types:
                    result.append(f'<font color="{colors["type"]}">{escaped}</font>')
                elif re.match(r'^0x[0-9a-fA-F]+$', token) or re.match(r'^\d+$', token):
                    result.append(f'<font color="{colors["number"]}">{escaped}</font>')
                elif token.isspace():
                    result.append(escaped.replace(' ', '&nbsp;'))
                else:
                    result.append(f'<font color="{colors["default"]}">{escaped}</font>')
            
            if in_string:
                result.append('</font>')
            
            return ''.join(result)
        
        # Process line by line
        lines = code.split('\n')
        highlighted_lines = [highlight_line(line) for line in lines]
        
        return '<br>'.join(highlighted_lines)

    def _markdown_to_html(self, text, accent_color="#c45d97"):
        """Convert markdown to styled HTML for IDA viewer"""
        import re
        
        # Use accent_color for headings, bullets, inline code
        colors = {
            "text": "#e0e0e0",
            "heading": accent_color,           # Use accent color
            "code_bg": "#0a0a0f",              # Very dark
            "code_text": "#74c1cf",            # Info cyan
            "inline_code": accent_color,       # Use accent color
            "bold": "#ffffff",
            "bullet": accent_color,            # Use accent color
            "link": "#74c1cf",                 # Info cyan
            "success": "#6ad9a9",
            "warning": "#e5c166",
            "error": "#e57260",
        }
        
        # IMPORTANT: Process code blocks BEFORE HTML escaping
        # to preserve code formatting
        def replace_code_block(match):
            lang = match.group(1) or ""
            code = match.group(2).strip()
            
            # Apply syntax highlighting (code is not yet escaped)
            highlighted = self._highlight_code(code, lang if lang else "c")
            
            return f'<table width="100%" cellpadding="8" cellspacing="0" style="background-color:{colors["code_bg"]}; margin: 0; border-radius: 4px; border: 1px solid #1a1a24;"><tr><td><font face="Consolas, Monaco, monospace" size="2">{highlighted}</font></td></tr></table>'
        
        # Extract code blocks first, before escaping
        text = re.sub(r'```(\w*)\n?(.*?)```', replace_code_block, text, flags=re.DOTALL)
        
        # Now escape the rest of the HTML (code blocks already processed)
        # We need to be careful - code blocks are now HTML, rest is not
        # Split by code blocks and escape only non-code parts
        html = text
        
        # Headers - NO extra line breaks (remove <br>)
        # Process #### first (most specific), then ###, ##, #
        html = re.sub(r'^#### (.+)$', f'<font size="2" color="{colors["heading"]}"><b>\\1</b></font>', html, flags=re.MULTILINE)
        html = re.sub(r'^### (.+)$', f'<font size="2" color="{colors["heading"]}"><b>\\1</b></font>', html, flags=re.MULTILINE)
        html = re.sub(r'^## (.+)$', f'<font size="2" color="{colors["heading"]}"><b>\\1</b></font>', html, flags=re.MULTILINE)
        html = re.sub(r'^# (.+)$', f'<font size="3" color="{colors["heading"]}"><b>\\1</b></font>', html, flags=re.MULTILINE)
        
        # Bold **text**
        html = re.sub(r'\*\*(.+?)\*\*', f'<font color="{colors["bold"]}"><b>\\1</b></font>', html)
        
        # Italic *text*
        html = re.sub(r'\*(.+?)\*', '<i>\\1</i>', html)
        
        # Inline code `code`
        html = re.sub(r'`([^`]+)`', f'<font face="Consolas, monospace" color="{colors["inline_code"]}">\\1</font>', html)
        
        # Bullet points
        html = re.sub(r'^- (.+)$', f'<font color="{colors["bullet"]}">•</font> <font color="{colors["text"]}">\\1</font>', html, flags=re.MULTILINE)
        html = re.sub(r'^\* (.+)$', f'<font color="{colors["bullet"]}">•</font> <font color="{colors["text"]}">\\1</font>', html, flags=re.MULTILINE)
        
        # Numbered lists
        html = re.sub(r'^(\d+)\. (.+)$', f'<font color="{colors["bullet"]}">\\1.</font> <font color="{colors["text"]}">\\2</font>', html, flags=re.MULTILINE)
        
        # Line breaks
        html = html.replace('\n', '<br>')
        
        # Wrap in default text color
        return f'<font size="2" color="{colors["text"]}">{html}</font>'

    def _export_json(self):
        """Export results to JSON file"""
        filename, _ = QFileDialog.getSaveFileName(
            self.parent, "Export Results", 
            os.path.expanduser("~/symbiotic_results.json"),
            "JSON Files (*.json)"
        )
        if filename:
            # Prepare AI results for export
            ai_data = {}
            for key, result in self.ai_results.items():
                if not result.get("hidden", False):
                    content = result.get("content", "")
                    if not content.startswith("Generating"):
                        ai_data[key] = {"type": result.get("type", "unknown"), "content": content}
            
            export_data = {
                "timestamp": datetime.datetime.now().isoformat(),
                "scanner": self.results.get("scanner", "opengrep"),
                "scan_type": self.results.get("scan_type", "unknown"),
                "total_functions": self.results.get("total_functions", 0),
                "vulnerabilities": self.vulns,
                "ai_results": ai_data
            }
            with open(filename, "w") as f:
                json.dump(export_data, f, indent=2)
            print(f"[Symbiotic] Results exported to {filename}")
            ida_kernwin.info(f"Results exported to:\n{filename}")

    def _export_html(self):
        """Export results to HTML file"""
        filename, _ = QFileDialog.getSaveFileName(
            self.parent, "Export Results", 
            os.path.expanduser("~/symbiotic_results.html"),
            "HTML Files (*.html)"
        )
        if filename:
            html_content = self._generate_html(for_export=True)
            with open(filename, "w") as f:
                f.write(html_content)
            print(f"[Symbiotic] HTML exported to {filename}")
            ida_kernwin.info(f"HTML exported to:\n{filename}")

    def _show_history(self):
        """Show scan history with diff comparison"""
        if len(_scan_history) < 1:
            ida_kernwin.info("No scan history available")
            return
        
        msg = "═══ SCAN HISTORY ═══\n\n"
        
        for i, h in enumerate(reversed(_scan_history[-10:])):
            ts = h["timestamp"][:19].replace("T", " ")
            count = h["vuln_count"]
            current = " ← CURRENT" if i == 0 else ""
            msg += f"{i+1}. {ts} - {count} issue(s){current}\n"
        
        # Show diff if we have at least 2 scans
        if len(_scan_history) >= 2:
            current_scan = _scan_history[-1]
            previous_scan = _scan_history[-2]
            
            # Get rule IDs from each scan
            current_rules = set()
            previous_rules = set()
            
            try:
                current_results = current_scan.get("results", {}).get("output", "")
                if current_results:
                    current_data = json.loads(current_results)
                    for v in current_data.get("fail_results", []):
                        current_rules.add(v.get("rule_id", ""))
                
                previous_results = previous_scan.get("results", {}).get("output", "")
                if previous_results:
                    previous_data = json.loads(previous_results)
                    for v in previous_data.get("fail_results", []):
                        previous_rules.add(v.get("rule_id", ""))
                
                new_vulns = current_rules - previous_rules
                fixed_vulns = previous_rules - current_rules
                
                msg += "\n═══ DIFF vs PREVIOUS ═══\n"
                
                if new_vulns:
                    msg += f"\n🔴 NEW ({len(new_vulns)}):\n"
                    for r in list(new_vulns)[:5]:
                        msg += f"  + {r}\n"
                    if len(new_vulns) > 5:
                        msg += f"  ... and {len(new_vulns) - 5} more\n"
                
                if fixed_vulns:
                    msg += f"\n🟢 FIXED ({len(fixed_vulns)}):\n"
                    for r in list(fixed_vulns)[:5]:
                        msg += f"  - {r}\n"
                    if len(fixed_vulns) > 5:
                        msg += f"  ... and {len(fixed_vulns) - 5} more\n"
                
                if not new_vulns and not fixed_vulns:
                    msg += "\nNo changes from previous scan.\n"
                    
            except Exception as e:
                msg += f"\n(Could not compute diff: {e})\n"
        
        ida_kernwin.info(msg)

    def _get_func_info_for_line(self, line_num):
        """Get function address and name for a given line number"""
        for func_ea, info in self.func_line_map.items():
            if info["start_line"] <= line_num <= info["end_line"]:
                return func_ea, info.get("name", "Unknown")
        return None, None

    def _group_vulnerabilities(self, vulns):
        """Group vulnerabilities by rule_id to reduce repetition"""
        from collections import OrderedDict
        
        grouped = OrderedDict()
        for v in vulns:
            rule_id = v.get("rule_id", "UNKNOWN")
            if rule_id not in grouped:
                grouped[rule_id] = {
                    "rule_id": rule_id,
                    "title": v.get("title", "Vulnerability"),
                    "severity": v.get("severity", "MEDIUM"),
                    "description": v.get("description", ""),
                    "cwe": v.get("cwe", ""),
                    "impact": v.get("impact", ""),
                    "references": v.get("references", []),
                    "impact_level": v.get("impact_level", "MEDIUM"),
                    "likelihood_level": v.get("likelihood_level", "LOW"),
                    "confidence_level": v.get("confidence_level", "MEDIUM"),
                    "occurrences": []
                }
            
            # Add this occurrence
            loc = v.get("location", {})
            line = loc.get("start_line", 0)
            func_addr, func_name = self._get_func_info_for_line(line) if line else (None, None)
            
            grouped[rule_id]["occurrences"].append({
                "line": line,
                "snippet": v.get("snippet", ""),
                "func_addr": func_addr,
                "func_name": func_name
            })
        
        return list(grouped.values())

    def _generate_html(self, for_export=False):
        """Generate HTML content"""
        
        # Colors
        bg_main = "#1e1e1e"
        bg_card = "#252526"
        text_white = "#ffffff"
        text_gray = "#858585"
        text_light = "#cccccc"
        brand_pink = "#c45d97"
        color_critical = "#ff4040"
        color_error = "#e57260"
        color_warning = "#e5c166"
        color_success = "#6ad9a9"
        color_info = "#74c1cf"
        color_link = "#3794ff"
        
        html = f'''<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
body {{ 
    background-color: {bg_main}; 
    color: {text_light}; 
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 13px;
    padding: 16px;
    margin: 0;
}}
a {{ color: {color_link}; text-decoration: none; cursor: pointer; }}
a:hover {{ text-decoration: underline; }}
.jump-btn {{
    background-color: #0e639c;
    color: white;
    padding: 4px 8px;
    border-radius: 3px;
    font-size: 11px;
    margin-left: 30px;
}}
</style>
</head>
<body>
'''
        if "error" in self.results:
            html += f'<font color="{color_error}"><b>Error:</b> {self._escape_html(self.results["error"])}</font>'
            html += '</body></html>'
            return html

        scan_type = self.results.get("scan_type", "single_function")
        scanner = self.results.get("scanner", "opengrep").upper()

        if scan_type == "all_functions":
            total = self.results.get("total_functions", 0)
            scanned = self.results.get("functions_scanned", 0)
            header_info = f"Scanner: {scanner} | Functions: {scanned}/{total}"
        else:
            func = self.results.get("function_name", "Unknown")
            addr = self.results.get("address", "Unknown")
            header_info = f"{self._escape_html(func)} @ {addr} | Scanner: {scanner}"

        # Filter vulnerabilities by severity
        filtered_vulns = self.vulns
        if self.current_filter != "ALL":
            filtered_vulns = [v for v in filtered_vulns if v.get("severity", "").upper() == self.current_filter]
        
        # Filter by function
        if self.current_func_filter != "ALL":
            def match_func(v):
                loc = v.get("location", {})
                line = loc.get("start_line", 0)
                if line:
                    _, func_name = self._get_func_info_for_line(line)
                    return func_name == self.current_func_filter
                return False
            filtered_vulns = [v for v in filtered_vulns if match_func(v)]
        
        # Filter by tag
        if self.current_tag_filter != "ALL":
            def match_tag(v):
                rule_id = v.get("rule_id", "UNKNOWN")
                tag = self.vuln_tags.get(rule_id)
                if self.current_tag_filter == "Untagged":
                    return tag is None
                elif self.current_tag_filter == "Confirmed":
                    return tag == "confirmed"
                elif self.current_tag_filter == "False Positive":
                    return tag == "false_positive"
                return True
            filtered_vulns = [v for v in filtered_vulns if match_tag(v)]

        # Group vulnerabilities by rule_id
        grouped_vulns = self._group_vulnerabilities(filtered_vulns)

        status_html = f'<font color="{color_success}">[OK] Scan completed successfully</font>'
        
        # Build filter info
        filter_info = []
        if self.current_filter != "ALL":
            filter_info.append(self.current_filter)
        if self.current_func_filter != "ALL":
            filter_info.append(f"func:{self.current_func_filter}")
        if self.current_tag_filter != "ALL":
            filter_info.append(f"tag:{self.current_tag_filter}")
        filter_str = f" (filtered: {', '.join(filter_info)})" if filter_info else ""
        
        html += f'''
<font size="2" color="{text_gray}">{header_info}</font><br>
{status_html}<br>
<font size="2" color="{text_gray}">Found {len(self.vulns)} issue(s) in {len(grouped_vulns)} unique rule(s){filter_str}</font>
<br><br>
'''
        
        if grouped_vulns:
            for g in grouped_vulns:
                html += self._render_grouped_vuln(g, bg_card, text_white, text_gray, text_light, 
                                          brand_pink, color_critical, color_error, 
                                          color_warning, color_success, color_info, for_export)
        else:
            html += f'''
<table width="100%" cellpadding="40" cellspacing="0">
<tr><td align="center">
<font size="4" color="{color_success}">[OK]</font><br><br>
<font size="3" color="{color_success}"><b>No Issues Found</b></font><br>
<font size="2" color="{text_gray}">No vulnerabilities match the current filter.</font>
</td></tr>
</table>
'''

        html += '</body></html>'
        return html

    def _render_grouped_vuln(self, g, bg_card, text_white, text_gray, text_light, brand_pink,
                             color_critical, color_error, color_warning, color_success, color_info, for_export=False):
        """Render a grouped vulnerability with multiple occurrences"""
        rule_id = g.get("rule_id", "UNKNOWN")
        title = g.get("title", "Vulnerability")
        severity = g.get("severity", "MEDIUM").upper()
        desc = g.get("description", "")
        cwe = g.get("cwe", "")
        impact_desc = g.get("impact", "")
        refs = g.get("references", [])
        occurrences = g.get("occurrences", [])
        
        impact_level = g.get("impact_level", "HIGH" if severity in ["CRITICAL", "HIGH"] else "MEDIUM")
        likelihood = g.get("likelihood_level", "LOW")
        confidence = g.get("confidence_level", "MEDIUM")
        
        sev_styles = {
            "CRITICAL": (color_critical, "#ffffff"),
            "HIGH": (color_error, "#ffffff"),
            "MEDIUM": (color_warning, "#1e1e1e"),
            "LOW": (color_success, "#1e1e1e"),
        }
        sev_bg, sev_fg = sev_styles.get(severity, ("#666666", "#ffffff"))
        
        occ_count = len(occurrences)
        occ_text = f"{occ_count} occurrence{'s' if occ_count > 1 else ''}"
        
        
        # Tag buttons (only when not exporting)
        vuln_id_safe = rule_id.replace(" ", "_")
        
        # Get current tag for this vuln (use safe ID with underscores)
        current_tag = self.vuln_tags.get(vuln_id_safe)
        tag_badge = ""
        if current_tag == "confirmed":
            tag_badge = f'<font color="{color_success}"> ✓ CONFIRMED</font>'
        elif current_tag == "false_positive":
            tag_badge = f'<font color="{color_error}"> ✗ FALSE POSITIVE</font>'
        
        tag_buttons = ""
        if not for_export:
            confirm_style = f'color:{color_success}; font-weight:bold;' if current_tag == "confirmed" else 'color:#666;'
            fp_style = f'color:{color_error}; font-weight:bold;' if current_tag == "false_positive" else 'color:#666;'
            tag_buttons = f'''<div style="float:right;">
<a href="tag://confirmed/{vuln_id_safe}" style="{confirm_style} text-decoration:none; padding:4px 8px;">[✓ Confirm]</a>
<a href="tag://false_positive/{vuln_id_safe}" style="{fp_style} text-decoration:none; padding:4px 8px;">[✗ False+]</a>
</div>'''
        
        html = f'''
<br>
<table width="100%" border="1" bordercolor="#555555" cellpadding="20" cellspacing="0" bgcolor="{bg_card}">
<tr><td>
{tag_buttons}
<font size="2" color="{text_gray}">{self._escape_html(rule_id)} | <font color="{brand_pink}">{occ_text}</font>{tag_badge}</font><br>
<font size="4" color="{text_white}"><b>{self._escape_html(title)}</b></font><br><br>
<table cellpadding="0" cellspacing="0"><tr>
<td bgcolor="{sev_bg}" style="padding: 3px 6px;"><font size="1" color="{sev_fg}"><b>{severity}</b></font></td>
<td style="padding-left: 12px;"><font size="2" color="{text_gray}">Impact: </font><font size="2" color="{text_white}"><b>{impact_level}</b></font></td>
<td style="padding-left: 12px;"><font size="2" color="{text_gray}">Likelihood: </font><font size="2" color="{text_white}"><b>{likelihood}</b></font></td>
<td style="padding-left: 12px;"><font size="2" color="{text_gray}">Confidence: </font><font size="2" color="{text_white}"><b>{confidence}</b></font></td>
</tr></table>
'''

        if cwe:
            html += f'''<br><br>
<table cellpadding="8" cellspacing="0" style="background-color:#2d2030;">
<tr><td style="border-left: 3px solid {brand_pink};"><font size="2" color="{brand_pink}"><b>{self._escape_html(cwe)}</b></font></td></tr>
</table>
'''

        if desc:
            html += f'''<br><br>
<font size="2" color="{text_gray}">Description</font><br>
<font size="2" color="{text_light}">{self._escape_html(desc[:700])}</font>
'''

        if impact_desc:
            html += f'''<br><br>
<font size="2" color="{text_gray}">Impact</font><br>
<font size="2" color="{text_light}">{self._escape_html(impact_desc[:500])}</font>
'''

        # Occurrences section - show all locations with jump links
        if occurrences:
            html += f'''<br><br>
<font size="2" color="{brand_pink}"><b>Occurrences ({occ_count})</b></font><br>
<table width="100%" cellpadding="8" cellspacing="2" style="margin-top: 8px;">
'''
            for i, occ in enumerate(occurrences):
                line = occ.get("line", 0)
                func_name = occ.get("func_name", "")
                func_addr = occ.get("func_addr")
                snippet = occ.get("snippet", "")
                
                # Jump link
                jump_link = ""
                if func_addr and not for_export:
                    jump_link = f'<a href="ida://{hex(func_addr)}" style="color:#3794ff; font-size:11px;">[Jump]</a>'
                
                func_display = f' in <b>{self._escape_html(func_name)}</b>' if func_name else ""
                
                # Alternating row colors
                row_bg = "#1e1e1e" if i % 2 == 0 else "#252526"
                
                html += f'''<tr style="background-color:{row_bg};">
<td style="padding: 8px; border-left: 2px solid {brand_pink};">
<font size="2" color="{text_white}">Line {line}{func_display} {jump_link}</font><br>
<font face="Consolas, Monaco, monospace" size="2" color="{color_info}">{self._escape_html(snippet[:150])}</font>
</td>
</tr>
'''
            html += '</table>'

        if refs:
            html += f'<br><br><font size="2" color="{text_gray}">Resources</font><br>'
            for r in refs[:3]:
                html += f'<a href="{self._escape_html(r)}"><font size="2">{self._escape_html(r)}</font></a><br>'

        # AI Action buttons
        if not for_export:
            vuln_id = rule_id.replace(" ", "_")
            html += f'''<br><br>
<table cellpadding="0" cellspacing="4"><tr>
<td>
<a href="ai://explain/{vuln_id}" style="
    display: inline-block;
    background: linear-gradient(180deg, #0e639c 0%, #0a4d7a 100%);
    color: #ffffff;
    padding: 8px 16px;
    border-radius: 4px;
    text-decoration: none;
    font-family: 'Segoe UI', Roboto, sans-serif;
    font-size: 12px;
    font-weight: 500;
    border: 1px solid #0d5a8f;
    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
">Explain with AI</a>
</td>
<td style="padding-left: 8px;">
<a href="ai://poc/{vuln_id}" style="
    display: inline-block;
    background: linear-gradient(180deg, #c45d97 0%, #a04b7d 100%);
    color: #ffffff;
    padding: 8px 16px;
    border-radius: 4px;
    text-decoration: none;
    font-family: 'Segoe UI', Roboto, sans-serif;
    font-size: 12px;
    font-weight: 500;
    border: 1px solid #b3528a;
    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
">Generate PoC</a>
</td>
</tr></table>
'''

        # AI Results section (same as before)
        explain_result = self._get_ai_result(rule_id, "explain")
        poc_result = self._get_ai_result(rule_id, "poc")
        has_explain = explain_result is not None
        has_poc = poc_result is not None
        
        if has_explain or has_poc:
            explain_hidden = explain_result.get("hidden", False) if has_explain else True
            poc_hidden = poc_result.get("hidden", False) if has_poc else True
            
            html += '<br><table width="100%" cellpadding="0" cellspacing="4" style="table-layout: fixed;"><tr>'
            
            if has_explain:
                content = explain_result.get("content", "")
                is_loading = content.startswith("Generating") and len(content) < 50
                tab_color = "#e5c166" if is_loading else "#c45d97"
                status = " (loading...)" if is_loading else ""
                toggle_text = "[show]" if explain_hidden else "[hide]"
                toggle_link = f'<a href="ai://toggle/{vuln_id}/explain" style="text-decoration:none; margin-left:8px;"><font color="#666">{toggle_text}</font></a>' if not is_loading else ""
                width = "50%" if has_poc else "100%"
                html += f'''<td width="{width}" style="background-color:#0a0a0f; padding: 8px 16px; border-top: 2px solid {tab_color}; border-radius: 6px 6px 0 0;">
<font size="2" color="{tab_color}"><b>AI Explanation{status}</b></font>{toggle_link}
</td>'''
            
            if has_poc:
                content = poc_result.get("content", "")
                is_loading = content.startswith("Generating") and len(content) < 50
                tab_color = "#e5c166" if is_loading else "#74c1cf"
                status = " (loading...)" if is_loading else ""
                toggle_text = "[show]" if poc_hidden else "[hide]"
                toggle_link = f'<a href="ai://toggle/{vuln_id}/poc" style="text-decoration:none; margin-left:8px;"><font color="#666">{toggle_text}</font></a>' if not is_loading else ""
                width = "50%" if has_explain else "100%"
                html += f'''<td width="{width}" style="background-color:#0a0a0f; padding: 8px 16px; border-top: 2px solid {tab_color}; border-radius: 6px 6px 0 0;">
<font size="2" color="{tab_color}"><b>Generated PoC{status}</b></font>{toggle_link}
</td>'''
            
            html += '</tr></table>'
            
            show_explain = has_explain and not explain_hidden
            show_poc = has_poc and not poc_hidden
            
            if show_explain or show_poc:
                html += '<table width="100%" cellpadding="0" cellspacing="4" style="table-layout: fixed;"><tr valign="top">'
                
                if has_explain and has_poc:
                    if show_explain:
                        explain_html = self._render_ai_content(explain_result, "#c45d97")
                        html += f'<td width="50%" style="background-color:#0a0a0f; padding: 12px; border-radius: 0 0 6px 6px; word-wrap: break-word;">{explain_html}</td>'
                    else:
                        html += '<td width="50%"></td>'
                    
                    if show_poc:
                        poc_html = self._render_ai_content(poc_result, "#74c1cf")
                        html += f'<td width="50%" style="background-color:#0a0a0f; padding: 12px; border-radius: 0 0 6px 6px; word-wrap: break-word;">{poc_html}</td>'
                    else:
                        html += '<td width="50%"></td>'
                else:
                    if show_explain:
                        explain_html = self._render_ai_content(explain_result, "#c45d97")
                        html += f'<td width="100%" style="background-color:#0a0a0f; padding: 12px; border-radius: 0 0 6px 6px; word-wrap: break-word;">{explain_html}</td>'
                    elif show_poc:
                        poc_html = self._render_ai_content(poc_result, "#74c1cf")
                        html += f'<td width="100%" style="background-color:#0a0a0f; padding: 12px; border-radius: 0 0 6px 6px; word-wrap: break-word;">{poc_html}</td>'
                
                html += '</tr></table>'

        html += '</td></tr></table>'
        return html

    def _render_vuln(self, v, bg_card, text_white, text_gray, text_light, brand_pink,
                     color_critical, color_error, color_warning, color_success, color_info, for_export=False):
        """Render a single vulnerability with navigation link"""
        rule_id = v.get("rule_id", "UNKNOWN")
        title = v.get("title", "Vulnerability")
        severity = v.get("severity", "MEDIUM").upper()
        desc = v.get("description", "")
        snippet = v.get("snippet", "")
        cwe = v.get("cwe", "")
        impact_desc = v.get("impact", "")
        refs = v.get("references", [])
        loc = v.get("location", {})
        line = loc.get("start_line", 0)
        
        # Get function address and name for navigation
        func_addr, func_name = self._get_func_info_for_line(line) if line else (None, None)
        
        impact_level = v.get("impact_level", "HIGH" if severity in ["CRITICAL", "HIGH"] else "MEDIUM")
        likelihood = v.get("likelihood_level", "LOW")
        confidence = v.get("confidence_level", "MEDIUM")
        
        sev_styles = {
            "CRITICAL": (color_critical, "#ffffff"),
            "HIGH": (color_error, "#ffffff"),
            "MEDIUM": (color_warning, "#1e1e1e"),
            "LOW": (color_success, "#1e1e1e"),
        }
        sev_bg, sev_fg = sev_styles.get(severity, ("#666666", "#ffffff"))
        
        # Navigation link - put on separate line, right-aligned
        nav_link = ""
        if func_addr and not for_export:
            nav_link = f'<div style="float:right;"><a href="ida://{hex(func_addr)}" class="jump-btn">Jump to Function</a></div>'
        
        # Function name display
        func_display = f" in <b>{self._escape_html(func_name)}</b>" if func_name else ""
        
        html = f'''
<br>
<table width="100%" border="1" bordercolor="#555555" cellpadding="20" cellspacing="0" bgcolor="{bg_card}">
<tr><td>
{nav_link}
<font size="2" color="{text_gray}">{self._escape_html(rule_id)} | Line {line}{func_display}</font><br>
<font size="4" color="{text_white}"><b>{self._escape_html(title)}</b></font><br><br>
<table cellpadding="0" cellspacing="0"><tr>
<td bgcolor="{sev_bg}" style="padding: 3px 6px;"><font size="1" color="{sev_fg}"><b>{severity}</b></font></td>
<td style="padding-left: 12px;"><font size="2" color="{text_gray}">Impact: </font><font size="2" color="{text_white}"><b>{impact_level}</b></font></td>
<td style="padding-left: 12px;"><font size="2" color="{text_gray}">Likelihood: </font><font size="2" color="{text_white}"><b>{likelihood}</b></font></td>
<td style="padding-left: 12px;"><font size="2" color="{text_gray}">Confidence: </font><font size="2" color="{text_white}"><b>{confidence}</b></font></td>
</tr></table>
'''

        if cwe:
            html += f'''<br><br>
<table cellpadding="8" cellspacing="0" style="background-color:#2d2030;">
<tr><td style="border-left: 3px solid {brand_pink};"><font size="2" color="{brand_pink}"><b>{self._escape_html(cwe)}</b></font></td></tr>
</table>
'''

        if desc:
            html += f'''<br><br>
<font size="2" color="{text_gray}">Description</font><br>
<font size="2" color="{text_light}">{self._escape_html(desc[:700])}</font>
'''

        if impact_desc:
            html += f'''<br><br>
<font size="2" color="{text_gray}">Impact</font><br>
<font size="2" color="{text_light}">{self._escape_html(impact_desc[:500])}</font>
'''

        if snippet:
            html += f'''<br><br>
<font size="2" color="{text_gray}">Vulnerable code example</font><br>
<table width="100%" cellpadding="12" cellspacing="0" style="background-color:#1e1e1e; margin-top: 8px;">
<tr><td><font face="Consolas, Monaco, monospace" size="2" color="{color_error}">{self._escape_html(snippet)}</font></td></tr>
</table>
'''

        if refs:
            html += f'<br><br><font size="2" color="{text_gray}">Resources</font><br>'
            for r in refs[:3]:
                html += f'<a href="{self._escape_html(r)}"><font size="2">{self._escape_html(r)}</font></a><br>'

        # AI Action buttons (VSCode-style)
        if not for_export:
            vuln_id = rule_id.replace(" ", "_")
            html += f'''<br><br>
<table cellpadding="0" cellspacing="4"><tr>
<td>
<a href="ai://explain/{vuln_id}" style="
    display: inline-block;
    background: linear-gradient(180deg, #0e639c 0%, #0a4d7a 100%);
    color: #ffffff;
    padding: 8px 16px;
    border-radius: 4px;
    text-decoration: none;
    font-family: 'Segoe UI', Roboto, sans-serif;
    font-size: 12px;
    font-weight: 500;
    border: 1px solid #0d5a8f;
    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
">Explain with AI</a>
</td>
<td style="padding-left: 8px;">
<a href="ai://poc/{vuln_id}" style="
    display: inline-block;
    background: linear-gradient(180deg, #6e40c9 0%, #553299 100%);
    color: #ffffff;
    padding: 8px 16px;
    border-radius: 4px;
    text-decoration: none;
    font-family: 'Segoe UI', Roboto, sans-serif;
    font-size: 12px;
    font-weight: 500;
    border: 1px solid #5c35a8;
    box-shadow: 0 2px 4px rgba(0,0,0,0.3);
">Generate PoC</a>
</td>
</tr></table>
'''

            # Check if there are AI results for this vuln
            explain_result = self._get_ai_result(vuln_id, "explain")
            poc_result = self._get_ai_result(vuln_id, "poc")
            
            has_explain = explain_result is not None
            has_poc = poc_result is not None
            
            if has_explain or has_poc:
                # Use fixed table layout for aligned 50/50 columns
                html += '<br><table width="100%" cellpadding="0" cellspacing="4" style="table-layout: fixed;"><tr>'
                
                # Determine if content is hidden
                explain_hidden = explain_result.get("hidden", False) if has_explain else True
                poc_hidden = poc_result.get("hidden", False) if has_poc else True
                
                # Tab headers - always 50% each when both exist
                if has_explain:
                    content = explain_result.get("content", "")
                    is_loading = content.startswith("Generating") and len(content) < 50
                    tab_color = "#e5c166" if is_loading else "#c45d97"
                    status = " (loading...)" if is_loading else ""
                    toggle_text = "[show]" if explain_hidden else "[hide]"
                    toggle_link = f'<a href="ai://toggle/{vuln_id}/explain" style="text-decoration:none; margin-left:8px;"><font color="#666">{toggle_text}</font></a>' if not is_loading else ""
                    width = "50%" if has_poc else "100%"
                    html += f'''<td width="{width}" style="background-color:#0a0a0f; padding: 8px 16px; border-top: 2px solid {tab_color}; border-radius: 6px 6px 0 0;">
<font size="2" color="{tab_color}"><b>AI Explanation{status}</b></font>{toggle_link}
</td>'''
                
                if has_poc:
                    content = poc_result.get("content", "")
                    is_loading = content.startswith("Generating") and len(content) < 50
                    tab_color = "#e5c166" if is_loading else "#74c1cf"
                    status = " (loading...)" if is_loading else ""
                    toggle_text = "[show]" if poc_hidden else "[hide]"
                    toggle_link = f'<a href="ai://toggle/{vuln_id}/poc" style="text-decoration:none; margin-left:8px;"><font color="#666">{toggle_text}</font></a>' if not is_loading else ""
                    width = "50%" if has_explain else "100%"
                    html += f'''<td width="{width}" style="background-color:#0a0a0f; padding: 8px 16px; border-top: 2px solid {tab_color}; border-radius: 6px 6px 0 0;">
<font size="2" color="{tab_color}"><b>Generated PoC{status}</b></font>{toggle_link}
</td>'''
                
                html += '</tr></table>'
                
                # Content area - only show if not hidden
                show_explain_content = has_explain and not explain_hidden
                show_poc_content = has_poc and not poc_hidden
                
                if show_explain_content or show_poc_content:
                    html += '<table width="100%" cellpadding="0" cellspacing="4" style="table-layout: fixed;"><tr valign="top">'
                    
                    if has_explain and has_poc:
                        # Both exist - show columns based on hidden state
                        if show_explain_content:
                            explain_html = self._render_ai_content(explain_result, "#c45d97")
                            html += f'''<td width="50%" style="background-color:#0a0a0f; padding: 12px; border-radius: 0 0 6px 6px; vertical-align: top; word-wrap: break-word;">
{explain_html}
</td>'''
                        else:
                            html += '<td width="50%"></td>'  # Empty placeholder for alignment
                        
                        if show_poc_content:
                            poc_html = self._render_ai_content(poc_result, "#74c1cf")
                            html += f'''<td width="50%" style="background-color:#0a0a0f; padding: 12px; border-radius: 0 0 6px 6px; vertical-align: top; word-wrap: break-word;">
{poc_html}
</td>'''
                        else:
                            html += '<td width="50%"></td>'  # Empty placeholder for alignment
                    else:
                        # Single result - full width
                        if show_explain_content:
                            explain_html = self._render_ai_content(explain_result, "#c45d97")
                            html += f'''<td width="100%" style="background-color:#0a0a0f; padding: 12px; border-radius: 0 0 6px 6px; vertical-align: top; word-wrap: break-word;">
{explain_html}
</td>'''
                        elif show_poc_content:
                            poc_html = self._render_ai_content(poc_result, "#74c1cf")
                            html += f'''<td width="100%" style="background-color:#0a0a0f; padding: 12px; border-radius: 0 0 6px 6px; vertical-align: top; word-wrap: break-word;">
{poc_html}
</td>'''
                    
                    html += '</tr></table>'

        html += '</td></tr></table>'
        return html

    def _parse_vulnerabilities(self):
        """Parse vulnerabilities from scan output"""
        output = self.results.get("output", "")
        if not output:
            return []
        try:
            data = json.loads(output)
            return data.get("fail_results", [])
        except:
            return []

    def _escape_html(self, text):
        """Escape HTML special characters"""
        if not text:
            return ""
        text = str(text)
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def _print_console_summary(self):
        """Print summary to IDA console"""
        print(f"\n[Symbiotic] Scan Results: {len(self.vulns)} issue(s) found")
        for v in self.vulns[:5]:
            title = v.get("title", "Unknown")
            severity = v.get("severity", "?")
            print(f"  - [{severity}] {title}")
        if len(self.vulns) > 5:
            print(f"  ... and {len(self.vulns) - 5} more")

    def OnClose(self, form):
        pass

    def Show(self, title="Symbiotic Scan Results"):
        return idaapi.PluginForm.Show(self, title, options=idaapi.PluginForm.WOPN_PERSIST)
