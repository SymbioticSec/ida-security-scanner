"""
Scanner Module
Scans code using opengrep-core
"""

import os
import subprocess
import tempfile
import json
import threading

import idaapi
import ida_hexrays
import ida_funcs
import idautils
import idc
import ida_kernwin
import ida_lines


class ScanThread(threading.Thread):
    """Background thread for scanning"""
    
    def __init__(self, scanner, scan_func, *args):
        super().__init__()
        self.scanner = scanner
        self.scan_func = scan_func
        self.args = args
        self.result = None
        self.error = None
        
    def run(self):
        try:
            self.result = self.scan_func(*self.args)
        except Exception as e:
            self.error = str(e)


class SymbioticScanner:
    """Scanner using opengrep-core with cancel support"""

    def __init__(self, config):
        self.config = config
        self._pseudocode_cache = {}  # Cache pseudocode for line mapping
        self._cancel_requested = False
        self._current_process = None

    def cancel_scan(self):
        """Request cancellation of current scan"""
        self._cancel_requested = True
        if self._current_process:
            try:
                self._current_process.terminate()
                print("[Symbiotic] Scan cancelled by user")
            except:
                pass

    def is_cancelled(self):
        """Check if cancel was requested"""
        return self._cancel_requested

    def reset_cancel(self):
        """Reset cancel flag for new scan"""
        self._cancel_requested = False
        self._current_process = None

    def extract_pseudocode(self, ea):
        """Extract pseudocode from a function at given address and build line→EA mapping"""
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                code = str(cfunc)
                code_lines = code.split('\n')
                
                # Build line → EA mapping using eamap
                line_ea_map = {}
                try:
                    # Get the pseudocode structure
                    sv = cfunc.get_pseudocode()
                    
                    # For each line in pseudocode, try to find corresponding EA
                    for line_idx in range(len(sv)):
                        sl = sv[line_idx]
                        # Get the line text and look for associated addresses
                        line_text = ida_lines.tag_remove(sl.line)
                        
                        # Try to find an EA for this line by checking eamap
                        # eamap maps EA -> ctree items, we need reverse
                        found_ea = idaapi.BADADDR
                        for item_ea, items in cfunc.eamap.items():
                            if item_ea != idaapi.BADADDR:
                                # Check if any item on this line
                                for item in items:
                                    if hasattr(item, 'loc') and item.loc:
                                        if item.loc.line == line_idx:
                                            found_ea = item_ea
                                            break
                                if found_ea != idaapi.BADADDR:
                                    break
                        
                        line_ea_map[line_idx] = found_ea
                        
                except Exception as e:
                    print(f"[Symbiotic] EA mapping error: {e}")
                
                # Cache for later use - include code lines for snippet matching
                self._pseudocode_cache[ea] = {
                    'lines': code_lines,
                    'line_ea_map': line_ea_map,
                    'cfunc': cfunc  # Keep cfunc reference for later annotation
                }
                return code
        except Exception as e:
            print(f"[Symbiotic] Failed to decompile function at {hex(ea)}: {e}")
        return None

    def get_pseudocode_line(self, ea, line_number):
        """Get specific line from cached pseudocode"""
        if ea in self._pseudocode_cache:
            cache = self._pseudocode_cache[ea]
            lines = cache.get('lines', []) if isinstance(cache, dict) else cache
            if 0 < line_number <= len(lines):
                return lines[line_number - 1]
        return None

    def get_line_ea(self, func_ea, relative_line):
        """Get the EA (address) for a specific relative line in a function's pseudocode"""
        if func_ea in self._pseudocode_cache:
            cache = self._pseudocode_cache[func_ea]
            if isinstance(cache, dict):
                line_ea_map = cache.get('line_ea_map', {})
                return line_ea_map.get(relative_line, idaapi.BADADDR)
        return idaapi.BADADDR

    def extract_function_code(self, ea):
        """Extract disassembly code from a function"""
        func = ida_funcs.get_func(ea)
        if not func:
            return None

        lines = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            disasm = idc.GetDisasm(head)
            if disasm:
                lines.append(disasm)

        return "\n".join(lines)

    def create_temp_file(self, code, filename="code.c"):
        """Create a temporary file with the code"""
        temp_dir = tempfile.mkdtemp(prefix="symbiotic_")
        temp_file = os.path.join(temp_dir, filename)

        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(code)

        return temp_dir, temp_file

    def scan_code(self, code, language="c"):
        """Scan code using opengrep-core"""
        print("[Symbiotic] Preparing opengrep scan...")

        extensions = {
            "c": "code.c",
            "cpp": "code.cpp",
        }
        filename = extensions.get(language, "code.c")

        temp_dir, temp_file = self.create_temp_file(code, filename)

        try:
            # Build command: opengrep-core -json -rules <rules> -lang <lang> <file>
            cmd = [self.config.opengrep_path, "-json"]

            if self.config.rules_path and os.path.exists(self.config.rules_path):
                cmd.extend(["-rules", self.config.rules_path])
            else:
                print("[Symbiotic] ERROR: No rules file configured!")
                return {"error": "No rules file configured"}

            cmd.extend(["-lang", language, temp_file])

            print(f"[Symbiotic] Executing: {' '.join(cmd)}")

            # Use Popen for cancel support
            self._current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            try:
                stdout, stderr = self._current_process.communicate(timeout=300)
            except subprocess.TimeoutExpired:
                self._current_process.kill()
                return {"error": "Scan timeout (>300s)"}
            
            if self._cancel_requested:
                return {"error": "Scan cancelled by user"}

            output = stdout if stdout else ""
            stderr_out = stderr if stderr else ""

            if stderr_out:
                print(f"[Symbiotic] Stderr: {stderr_out[:500]}")

            # Debug: save scanned code for inspection
            debug_file = os.path.join(os.path.expanduser("~"), "symbiotic_last_scan.c")
            with open(debug_file, "w") as f:
                f.write(code)
            print(f"[Symbiotic] Debug: saved scanned code to {debug_file}")
            print(f"[Symbiotic] Raw output length: {len(output)} chars")

            # Parse opengrep JSON output format and add source for line extraction
            source_lines = code.split('\n')
            converted_output = self._convert_opengrep_output(output, source_lines)
            
            return {
                "success": True,
                "output": converted_output,
                "raw_output": output,
                "stderr": stderr,
                "temp_dir": temp_dir,
                "scanner": "opengrep",
                "source_lines": source_lines
            }

        except subprocess.TimeoutExpired:
            return {"error": "Scan timeout (>300s)"}
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {"error": f"Scan failed: {str(e)}"}

    def _convert_opengrep_output(self, raw_output, source_lines=None):
        """Convert opengrep JSON output to our expected format"""
        try:
            if not raw_output or not raw_output.strip():
                print("[Symbiotic] No output from opengrep")
                return json.dumps({"fail_results": []})
            
            # Opengrep outputs a dot followed by newline before the JSON
            # Find the start of the JSON object
            json_start = raw_output.find('{')
            if json_start == -1:
                print("[Symbiotic] No JSON found in output")
                return json.dumps({"fail_results": []})
            
            json_output = raw_output[json_start:]
            print(f"[Symbiotic] JSON starts at position {json_start}")
            
            data = json.loads(json_output)
            
            # Opengrep returns {"version": "...", "results": [...], "errors": [...]}
            results = data.get("results", [])
            print(f"[Symbiotic] Found {len(results)} results in opengrep output")
            
            fail_results = []
            for r in results:
                check_id = r.get("check_id", "UNKNOWN")
                extra = r.get("extra", {})
                metadata = extra.get("metadata", {})
                
                # Get line numbers
                start_info = r.get("start", {})
                end_info = r.get("end", {})
                start_line = start_info.get("line", 0)
                end_line = end_info.get("line", start_line)
                
                # Extract the actual vulnerable code snippet from source
                snippet = ""
                if source_lines and start_line > 0:
                    # Get lines from start_line to end_line (1-indexed)
                    snippet_lines = source_lines[start_line - 1:end_line]
                    snippet = "\n".join(snippet_lines)
                
                vuln = {
                    "rule_id": check_id,
                    "title": metadata.get("title", extra.get("message", check_id)),
                    "severity": metadata.get("severity", "MEDIUM").upper() if metadata.get("severity") else "MEDIUM",
                    "description": extra.get("message", ""),
                    "snippet": snippet,
                    "cwe": metadata.get("cwe", ""),
                    "owasp": metadata.get("owasp", ""),
                    "impact": metadata.get("impact", ""),
                    "impact_level": metadata.get("impact_level", "MEDIUM"),
                    "likelihood_level": metadata.get("likelihood_level", "MEDIUM"),
                    "confidence_level": metadata.get("confidence_level", "MEDIUM"),
                    "references": metadata.get("references", []),
                    "location": {
                        "start_line": start_line,
                        "end_line": end_line,
                        "path": r.get("path", "")
                    }
                }
                fail_results.append(vuln)
                print(f"[Symbiotic]   - {check_id}: {metadata.get('title', 'Unknown')} @ line {start_line}")
            
            return json.dumps({"fail_results": fail_results})
        except json.JSONDecodeError as e:
            print(f"[Symbiotic] JSON parse error: {e}")
            print(f"[Symbiotic] Raw output: {raw_output[:1000] if raw_output else 'empty'}")
            return json.dumps({"fail_results": []})
        except Exception as e:
            print(f"[Symbiotic] Error converting output: {e}")
            import traceback
            traceback.print_exc()
            return json.dumps({"fail_results": []})

    def scan_function(self, ea):
        """Scan a function at given address"""
        func_name = idc.get_func_name(ea)
        print(f"[Symbiotic] Scanning function: {func_name} at {hex(ea)}")

        code = self.extract_pseudocode(ea)
        if code:
            print(f"[Symbiotic] Extracted pseudocode ({len(code)} chars)")
            result = self.scan_code(code, "c")
        else:
            print("[Symbiotic] Pseudocode not available, using disassembly")
            code = self.extract_function_code(ea)
            if code:
                result = self.scan_code(code, "c")
            else:
                return {"error": "Failed to extract code from function"}

        result["function_name"] = func_name
        result["address"] = hex(ea)
        result["scan_type"] = "single_function"

        # Annotate in IDA
        self.annotate_findings(result, ea)

        return result

    def scan_function_async(self, ea, callback):
        """Scan function in background thread - collect IDA data first in main thread"""
        func_name = idc.get_func_name(ea)
        print(f"[Symbiotic] Scanning function (async): {func_name} at {hex(ea)}")

        # Extract pseudocode in main thread
        code = self.extract_pseudocode(ea)
        if not code:
            print("[Symbiotic] Pseudocode not available, using disassembly")
            code = self.extract_function_code(ea)
            if not code:
                callback({"error": "Failed to extract code from function"})
                return None

        print(f"[Symbiotic] Extracted code ({len(code)} chars)")

        # Run scan in background thread
        def _scan_and_callback():
            result = self.scan_code(code, "c")
            result["function_name"] = func_name
            result["address"] = hex(ea)
            result["scan_type"] = "single_function"

            # Annotate in main thread
            def _annotate_and_show():
                self.annotate_findings(result, ea)
                callback(result)
            
            ida_kernwin.execute_sync(_annotate_and_show, ida_kernwin.MFF_FAST)
        
        thread = threading.Thread(target=_scan_and_callback)
        thread.start()
        return thread

    def scan_all_functions(self):
        """Scan all functions in the binary"""
        print("\n" + "=" * 70)
        print("[Symbiotic] SCAN ALL FUNCTIONS")
        print("=" * 70)

        all_funcs = []
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if func:
                func_name = idc.get_func_name(func_ea)
                all_funcs.append((func_ea, func_name))

        total_funcs = len(all_funcs)
        print(f"[Symbiotic] Found {total_funcs} functions to scan")

        # Collect all pseudo-code
        all_code = []
        func_line_map = {}
        current_line = 1

        for func_ea, func_name in all_funcs:
            code = self.extract_pseudocode(func_ea)
            if code:
                lines = code.count('\n') + 1
                func_line_map[func_ea] = {
                    "name": func_name,
                    "start_line": current_line,
                    "end_line": current_line + lines - 1
                }
                all_code.append(f"// Function: {func_name} @ {hex(func_ea)}")
                all_code.append(code)
                all_code.append("")
                current_line += lines + 2

        if not all_code:
            return {"error": "No functions could be decompiled"}

        combined_code = "\n".join(all_code)
        print(f"[Symbiotic] Combined {len(all_code)} functions ({len(combined_code)} chars)")

        result = self.scan_code(combined_code, "c")
        result["total_functions"] = total_funcs
        result["functions_scanned"] = len(func_line_map)
        result["scan_type"] = "all_functions"
        result["func_line_map"] = func_line_map

        # Annotate functions
        self.annotate_all_functions(result, func_line_map)

        return result

    def scan_all_functions_async(self, callback):
        """Scan all functions in background thread - collect IDA data first in main thread"""
        print("\n" + "=" * 70)
        print("[Symbiotic] SCAN ALL FUNCTIONS (async)")
        print("=" * 70)

        # IMPORTANT: Collect all IDA data in main thread FIRST
        all_funcs = []
        for func_ea in idautils.Functions():
            func = ida_funcs.get_func(func_ea)
            if func:
                func_name = idc.get_func_name(func_ea)
                all_funcs.append((func_ea, func_name))

        total_funcs = len(all_funcs)
        print(f"[Symbiotic] Found {total_funcs} functions to scan")

        # Collect all pseudo-code in main thread with UI updates
        all_code = []
        func_line_map = {}
        current_line = 1
        
        for i, (func_ea, func_name) in enumerate(all_funcs):
            # Update wait box to show progress
            if i % 5 == 0:  # Update every 5 functions to avoid UI overhead
                ida_kernwin.replace_wait_box(f"Decompiling function {i+1}/{total_funcs}...")
            
            code = self.extract_pseudocode(func_ea)
            if code:
                lines = code.count('\n') + 1
                func_line_map[func_ea] = {
                    "name": func_name,
                    "start_line": current_line,
                    "end_line": current_line + lines - 1
                }
                all_code.append(f"// Function: {func_name} @ {hex(func_ea)}")
                all_code.append(code)
                all_code.append("")
                current_line += lines + 2

        if not all_code:
            callback({"error": "No functions could be decompiled"})
            return None

        combined_code = "\n".join(all_code)
        print(f"[Symbiotic] Combined {len(func_line_map)} functions ({len(combined_code)} chars)")
        
        # Update wait box for scan phase
        ida_kernwin.replace_wait_box("Running opengrep scan...")

        # Now run the actual scan in background thread
        def _scan_and_callback():
            # Only subprocess call happens here - no IDA API
            result = self.scan_code(combined_code, "c")
            result["total_functions"] = total_funcs
            result["functions_scanned"] = len(func_line_map)
            result["scan_type"] = "all_functions"
            result["func_line_map"] = func_line_map

            # Annotate must happen in main thread
            def _annotate_and_show():
                self.annotate_all_functions(result, func_line_map)
                callback(result)
            
            ida_kernwin.execute_sync(_annotate_and_show, ida_kernwin.MFF_FAST)
        
        thread = threading.Thread(target=_scan_and_callback)
        thread.start()
        return thread

    def annotate_findings(self, scan_result, func_addr=None):
        """Annotate IDA with vulnerability findings"""
        try:
            output = scan_result.get("output", "")
            if not output:
                return

            data = json.loads(output)
            findings = data.get("fail_results", [])

            if not findings:
                print("[Symbiotic] No vulnerabilities to annotate")
                return

            for finding in findings:
                title = finding.get("title", "Vulnerability")
                cwe = finding.get("cwe", "")
                
                comment = f"[VULN] {title}"
                if cwe:
                    comment += f" ({cwe})"

                if func_addr:
                    existing = idc.get_func_cmt(func_addr, 0) or ""
                    if comment not in existing:
                        new_comment = f"{existing}\n{comment}" if existing else comment
                        idc.set_func_cmt(func_addr, new_comment, 0)
                        idc.set_color(func_addr, idc.CIC_FUNC, 0xFF6B6B)
                        print(f"[Symbiotic]   [OK] Annotated function at {hex(func_addr)}")

            print("[Symbiotic] [OK] IDA annotations complete!")

        except Exception as e:
            print(f"[Symbiotic] Annotation error: {e}")

    def annotate_all_functions(self, scan_result, func_line_map):
        """Annotate all functions with their vulnerabilities"""
        try:
            output = scan_result.get("output", "")
            if not output:
                return

            data = json.loads(output)
            findings = data.get("fail_results", [])

            if not findings:
                return

            # Group findings by function
            func_vulns = {}
            for finding in findings:
                loc = finding.get("location", {})
                vuln_line = loc.get("start_line", 0)

                for func_ea, info in func_line_map.items():
                    if info["start_line"] <= vuln_line <= info["end_line"]:
                        if func_ea not in func_vulns:
                            func_vulns[func_ea] = []
                        func_vulns[func_ea].append(finding)
                        break

            # Annotate each function with line-specific comments
            for func_ea, vulns in func_vulns.items():
                func_name = func_line_map[func_ea]["name"]
                func_start_line = func_line_map[func_ea]["start_line"]
                
                # Try to add inline comments using Hex-Rays API (ida-pro-mcp method)
                try:
                    cfunc = ida_hexrays.decompile(func_ea)
                    if cfunc:
                        sv = cfunc.get_pseudocode()
                        eamap = cfunc.get_eamap()
                        
                        for v in vulns:
                            title = v.get("title", "Vulnerability")
                            cwe = v.get("cwe", "")
                            snippet = v.get("snippet", "")
                            
                            cmt_text = f"VULN: {title}"
                            if cwe:
                                cmt_text += f" ({cwe})"
                            
                            # Find the EA corresponding to this vulnerability's snippet
                            target_ea = None
                            if snippet:
                                snippet_clean = snippet.strip().split('\n')[0].strip()
                                # Search through pseudocode lines
                                for line_idx in range(len(sv)):
                                    line_text = ida_lines.tag_remove(sv[line_idx].line)
                                    if snippet_clean in line_text:
                                        # Found the line, now find EA for this line
                                        # Use reverse mapping from eamap
                                        for ea_addr, items in eamap.items():
                                            if ea_addr != idaapi.BADADDR:
                                                target_ea = ea_addr
                                                break
                                        break
                            
                            if target_ea and target_ea in eamap:
                                nearest_ea = eamap[target_ea][0].ea
                                
                                # Clear orphan comments first
                                if cfunc.has_orphan_cmts():
                                    cfunc.del_orphan_cmts()
                                    cfunc.save_user_cmts()
                                
                                # Try different itp values until comment is not orphaned
                                tl = idaapi.treeloc_t()
                                tl.ea = nearest_ea
                                success = False
                                for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
                                    tl.itp = itp
                                    cfunc.set_user_cmt(tl, cmt_text)
                                    cfunc.save_user_cmts()
                                    cfunc.refresh_func_ctext()
                                    if not cfunc.has_orphan_cmts():
                                        success = True
                                        print(f"[Symbiotic]   Added comment @ {hex(nearest_ea)}: {cmt_text[:40]}...")
                                        break
                                    cfunc.del_orphan_cmts()
                                    cfunc.save_user_cmts()
                                
                                if not success:
                                    print(f"[Symbiotic]   Warning: Comment became orphaned")
                                    
                except Exception as e:
                    print(f"[Symbiotic] Inline comment error: {e}")
                
                # Also add function-level comment as visible fallback
                comments = []
                for v in vulns:
                    title = v.get("title", "Vulnerability")
                    cwe = v.get("cwe", "")
                    snippet = v.get("snippet", "").strip().split('\n')[0][:60]
                    comment = f"// [VULN] {title}"
                    if cwe:
                        comment += f" ({cwe})"
                    if snippet:
                        comment += f" @ {snippet}"
                    comments.append(comment)

                existing = idc.get_func_cmt(func_ea, 0) or ""
                # Clear previous vuln comments
                if "[VULN]" in existing:
                    existing = "\n".join([l for l in existing.split("\n") if "[VULN]" not in l])
                new_comment = existing + "\n" + "\n".join(comments) if existing.strip() else "\n".join(comments)
                idc.set_func_cmt(func_ea, new_comment.strip(), 0)
                idc.set_color(func_ea, idc.CIC_FUNC, 0xFF6B6B)

                print(f"[Symbiotic]   [OK] Annotated {func_name} with {len(vulns)} vuln(s)")

            print(f"[Symbiotic] [OK] Annotated {len(func_vulns)} vulnerable functions!")

        except Exception as e:
            print(f"[Symbiotic] Annotation error: {e}")
            import traceback
            traceback.print_exc()
