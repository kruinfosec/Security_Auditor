#!/usr/bin/env python3
# Main window implementation for Security Auditor Tool

import os
import tkinter as tk
import json
from tkinter import ttk, messagebox, filedialog
import threading
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

from core.scanner import Scanner
from core.remediation import RemediationManager
from integrations.nvd_client import NVDClient
from utils.export import ExportManager
from utils.system import get_platform_info


class ScanTab(ttk.Frame):
    """Tab for running security scans."""
    
    def __init__(self, parent, scanner: Scanner, platform_info: dict):
        super().__init__(parent)
        self.scanner = scanner
        self.platform_info = platform_info
        self.current_scan_id = None
        self.check_vars = {}  # Track checkbox states
        self.check_widgets = {}  # Store references to check widgets
        self.nvd_client = NVDClient()
        self.init_ui()
        
    def init_ui(self):
        """Initialize the UI components."""
        # Main frame layout
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=3)
        self.rowconfigure(0, weight=1)
        
        # Create a frame for the check selection
        check_frame = ttk.LabelFrame(self, text="Available Checks")
        check_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Create a frame for the scan results
        results_frame = ttk.LabelFrame(self, text="Scan Results")
        results_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        
        # Populate check selection frame
        self.create_check_selection(check_frame)
        
        # Populate results frame
        self.create_results_view(results_frame)
        
        # Create controls frame
        controls_frame = ttk.Frame(self)
        controls_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        
        # Add buttons
        self.scan_button = ttk.Button(controls_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(controls_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.select_all_button = ttk.Button(controls_frame, text="Select All", command=self.select_all_checks)
        self.select_all_button.pack(side=tk.LEFT, padx=5)
        
        self.deselect_all_button = ttk.Button(controls_frame, text="Deselect All", command=self.deselect_all_checks)
        self.deselect_all_button.pack(side=tk.LEFT, padx=5)
        
        self.export_button = ttk.Button(controls_frame, text="Export Results", command=self.export_results, state=tk.DISABLED)
        self.export_button.pack(side=tk.RIGHT, padx=5)
        
    def create_check_selection(self, parent):
        """Create the check selection panel."""
        # Create a canvas with scrollbar for the check list
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Get available checks
        available_checks = self.scanner.get_available_checks()
        
        # Group checks by severity
        severities = {"critical": [], "high": [], "medium": [], "low": []}
        for check_id, check_info in available_checks.items():
            severity = check_info.get("severity", "medium").lower()
            if severity in severities:
                severities[severity].append((check_id, check_info))
        
        # Add checks to UI grouped by severity
        row = 0
        severity_colors = {
            "critical": "#FF5252",  # Red
            "high": "#FFA726",      # Orange
            "medium": "#FFEE58",    # Yellow
            "low": "#66BB6A"        # Green
        }
        
        for severity in ["critical", "high", "medium", "low"]:
            if severities[severity]:
                # Create a header for the severity group
                header_frame = ttk.Frame(scrollable_frame)
                header_frame.grid(row=row, column=0, sticky="ew", pady=(10, 5))
                
                # Add a color indicator
                color_indicator = tk.Frame(header_frame, width=16, height=16, bg=severity_colors[severity])
                color_indicator.pack(side=tk.LEFT, padx=(5, 10))
                
                # Add a label
                severity_label = ttk.Label(header_frame, text=f"{severity.capitalize()} Severity ({len(severities[severity])})")
                severity_label.pack(side=tk.LEFT)
                
                row += 1
                
                # Add checks for this severity
                for check_id, check_info in severities[severity]:
                    check_frame = ttk.Frame(scrollable_frame)
                    check_frame.grid(row=row, column=0, sticky="ew", padx=20)
                    
                    # Create a variable to track checkbox state
                    self.check_vars[check_id] = tk.BooleanVar(value=True)
                    
                    # Create a checkbox
                    check_box = ttk.Checkbutton(
                        check_frame, 
                        text=check_info["title"],
                        variable=self.check_vars[check_id]
                    )
                    check_box.pack(side=tk.LEFT, anchor="w")
                    
                    # Store reference to the widget
                    self.check_widgets[check_id] = check_box
                    
                    # Add tooltip with description
                    self.create_tooltip(check_box, check_info["description"])
                    
                    row += 1
    
    def create_tooltip(self, widget, text):
        """Create a tooltip for a widget."""
        # This is a simple tooltip implementation
        def enter(event):
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() + 25
            y += widget.winfo_rooty() + 25
            
            # Create a toplevel window
            self.tooltip = tk.Toplevel(widget)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.wm_geometry(f"+{x}+{y}")
            
            label = ttk.Label(self.tooltip, text=text, wraplength=250,
                             background="#ffffe0", relief="solid", borderwidth=1)
            label.pack(ipadx=5, ipady=5)
            
        def leave(event):
            if hasattr(self, "tooltip"):
                self.tooltip.destroy()
                
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)
    
    def create_results_view(self, parent):
        """Create the results view panel."""
        # Create a frame for the results header
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill="x", padx=5, pady=5)
        
        # Add scan status label
        self.status_label = ttk.Label(header_frame, text="No scan running")
        self.status_label.pack(side=tk.LEFT)
        
        # Add progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(header_frame, variable=self.progress_var, length=200)
        self.progress_bar.pack(side=tk.RIGHT)
        
        # Create a treeview for the results
        columns = ("Status", "Title", "Severity", "CVEs")
        self.results_tree = ttk.Treeview(parent, columns=columns, show="headings")
        
        # Define headings
        for col in columns:
            self.results_tree.heading(col, text=col)
            
        # Set column widths
        self.results_tree.column("Status", width=80, anchor="center")
        self.results_tree.column("Title", width=300)
        self.results_tree.column("Severity", width=80, anchor="center")
        self.results_tree.column("CVEs", width=100, anchor="center")
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        # Add treeview and scrollbar to frame
        self.results_tree.pack(side=tk.LEFT, fill="both", expand=True)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        
        # Add detail frame below the treeview
        self.detail_frame = ttk.LabelFrame(parent, text="Check Details")
        self.detail_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add text widget for details
        self.detail_text = tk.Text(self.detail_frame, wrap=tk.WORD, height=10)
        self.detail_text.pack(side=tk.LEFT, fill="both", expand=True)
        
        # Add scrollbar for details
        detail_scrollbar = ttk.Scrollbar(self.detail_frame, orient="vertical", command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=detail_scrollbar.set)
        detail_scrollbar.pack(side=tk.RIGHT, fill="y")
        
        # Add button for remediation
        self.remediate_button = ttk.Button(self.detail_frame, text="Fix Issue", command=self.remediate_selected, state=tk.DISABLED)
        self.remediate_button.pack(side=tk.BOTTOM, padx=8, pady=5)
        
        # Bind treeview selection
        self.results_tree.bind("<<TreeviewSelect>>", self.on_result_selected)
    
    def select_all_checks(self):
        """Select all checks."""
        for var in self.check_vars.values():
            var.set(True)
    
    def deselect_all_checks(self):
        """Deselect all checks."""
        for var in self.check_vars.values():
            var.set(False)
    
    def start_scan(self):
        """Start a new security scan."""
        # Get selected checks
        selected_checks = [check_id for check_id, var in self.check_vars.items() if var.get()]
        
        if not selected_checks:
            messagebox.showwarning("No Checks Selected", "Please select at least one check to run.")
            return
        
        # Update UI
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.DISABLED)
        self.results_tree.delete(*self.results_tree.get_children())
        self.detail_text.delete(1.0, tk.END)
        self.status_label.config(text="Scan in progress...")
        self.progress_var.set(0)
        
        # Start the scan in a separate thread
        self.current_scan_id = self.scanner.start_scan(
            selected_checks,
            self.platform_info,
            progress_callback=self.update_progress,
            complete_callback=self.scan_complete
        )
    
    def stop_scan(self):
        """Stop the current scan."""
        # Currently the scanner doesn't support stopping a scan in progress
        # This is a placeholder for future implementation
        messagebox.showinfo("Not Implemented", "Stopping a scan is not yet implemented.")
    
    def update_progress(self, check_id: str, result: dict):
        """Update the progress and results display."""
        # Add result to treeview
        passed = result.get("passed", False)
        status = "✅" if passed else "❌"
        severity = result.get("severity", "").capitalize()
        title = result.get("title", check_id)
        cve_count = len(result.get("cve_ids", []))
        
        item_id = self.results_tree.insert("", "end", values=(status, title, severity, cve_count))
        
        # Store the check_id and result in the item
        self.results_tree.item(item_id, tags=(check_id,))
        
        # Update progress bar
        total_checks = len(self.check_vars)
        completed = len(self.results_tree.get_children())
        progress = completed / total_checks if total_checks > 0 else 0
        self.progress_var.set(progress * 100)
        
        # Force update of the UI
        self.update_idletasks()
    
    def scan_complete(self, scan_result):
        """Handle scan completion."""
        # Update UI
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.export_button.config(state=tk.NORMAL)
        
        # Update status
        self.status_label.config(
            text=f"Scan complete: {scan_result.passed_count} passed, {scan_result.failed_count} failed"
        )
        
        # Set progress to 100%
        self.progress_var.set(100)
        
        # Show completion message
        messagebox.showinfo(
            "Scan Complete",
            f"Security scan completed.\n\n"
            f"Checks passed: {scan_result.passed_count}\n"
            f"Checks failed: {scan_result.failed_count}\n"
            f"Total checks: {scan_result.check_count}\n"
            f"Duration: {scan_result.duration:.2f} seconds"
        )
    
    def on_result_selected(self, event):
        """Handle selection of a result item."""
        # Get selected item
        selection = self.results_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        tags = self.results_tree.item(item, "tags")
        check_id = tags[0] if tags else None
        
        if not check_id or not self.current_scan_id:
            return
            
        # Load the scan result
        scan_result = self.scanner.load_scan_result(self.current_scan_id)
        if not scan_result:
            return
            
        # Get the specific check result
        result = scan_result.results.get(check_id)
        if not result:
            return
            
        # Display details
        self.detail_text.delete(1.0, tk.END)
        
        # Add basic info
        self.detail_text.insert(tk.END, f"Check ID: {check_id}\n")
        self.detail_text.insert(tk.END, f"Title: {result.get('title', '')}\n")
        self.detail_text.insert(tk.END, f"Description: {result.get('description', '')}\n")
        self.detail_text.insert(tk.END, f"Severity: {result.get('severity', '').capitalize()}\n")
        self.detail_text.insert(tk.END, f"Status: {'Passed' if result.get('passed', False) else 'Failed'}\n\n")
        
        # Add details
        self.detail_text.insert(tk.END, "Details:\n")
        details = result.get("details", {})
        for key, value in details.items():
            self.detail_text.insert(tk.END, f"- {key}: {value}\n")
            
        # Add CVEs
        cve_ids = result.get("cve_ids", [])
        if cve_ids:
            self.detail_text.insert(tk.END, "\nAssociated CVEs:\n")
            for cve_id in cve_ids:
                self.detail_text.insert(tk.END, f"- {cve_id}\n")
                
                # Try to fetch CVE details
                try:
                    cve_details = self.nvd_client.get_cve_details(cve_id)
                    if cve_details:
                        self.detail_text.insert(tk.END, f"  Severity: {cve_details.get('severity', 'Unknown')}\n")
                        self.detail_text.insert(tk.END, f"  Description: {cve_details.get('description', 'No description')}\n")
                except Exception as e:
                    self.detail_text.insert(tk.END, f"  Error fetching details: {str(e)}\n")
        
        # Enable remediation button if the check failed
        if not result.get("passed", False):
            self.remediate_button.config(state=tk.NORMAL)
        else:
            self.remediate_button.config(state=tk.DISABLED)
    
    def remediate_selected(self):
        """Remediate the selected check."""
        # Get selected item
        selection = self.results_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        tags = self.results_tree.item(item, "tags")
        check_id = tags[0] if tags else None
        
        if not check_id:
            return
            
        # Get the remediation script
        remediation_script = self.scanner.get_remediation_script(check_id)
        
        # Show the script and ask for confirmation
        dialog = RemediationDialog(self, check_id, remediation_script)
        self.wait_window(dialog)
        
        if dialog.confirmed:
            # Apply remediation
            result = self.scanner.remediate(check_id)
            
            if result.get("success", False):
                messagebox.showinfo("Remediation", "Remediation applied successfully.")
                
                # Update the UI to reflect the fixed issue
                self.results_tree.item(item, values=("✅", *self.results_tree.item(item)["values"][1:]))
                self.remediate_button.config(state=tk.DISABLED)
            else:
                messagebox.showerror("Remediation Failed", result.get("message", "Unknown error"))
    
    def export_results(self):
        """Export scan results."""
        if not self.current_scan_id:
            messagebox.showwarning("No Results", "No scan results to export.")
            return
            
        # Ask for export format
        formats = ["HTML", "Text", "JSON"]
        dialog = ExportDialog(self, formats)
        self.wait_window(dialog)
        
        if not dialog.selected_format:
            return
            
        # Ask for file location
        extensions = {
            "HTML": ".html",
            "Text": ".txt",
            "JSON": ".json"
        }
        
        ext = extensions.get(dialog.selected_format, ".txt")
        filename = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[(f"{dialog.selected_format} Files", f"*{ext}"), ("All Files", "*.*")],
            initialfile=f"security_scan_{self.current_scan_id}{ext}"
        )
        
        if not filename:
            return
            
        # Export the results
        try:
            export_manager = ExportManager()
            export_manager.export_scan(self.current_scan_id, filename, dialog.selected_format.lower())
            messagebox.showinfo("Export Successful", f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))


class HistoryTab(ttk.Frame):
    """Tab for viewing scan history."""
    
    def __init__(self, parent, scanner: Scanner):
        super().__init__(parent)
        self.scanner = scanner
        self.init_ui()
        
    def init_ui(self):
        """Initialize the UI components."""
        # Main frame layout
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        
        # Create a frame for the scan history
        history_frame = ttk.LabelFrame(self, text="Scan History")
        history_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Create a treeview for the scan history
        columns = ("Date", "Checks", "Passed", "Failed", "Duration")
        self.history_tree = ttk.Treeview(history_frame, columns=columns, show="headings")
        
        # Define headings
        for col in columns:
            self.history_tree.heading(col, text=col)
            
        # Set column widths
        self.history_tree.column("Date", width=150)
        self.history_tree.column("Checks", width=80, anchor="center")
        self.history_tree.column("Passed", width=80, anchor="center")
        self.history_tree.column("Failed", width=80, anchor="center")
        self.history_tree.column("Duration", width=100, anchor="center")
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(history_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        
        # Add treeview and scrollbar to frame
        self.history_tree.pack(side=tk.LEFT, fill="both", expand=True)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        
        # Add buttons
        button_frame = ttk.Frame(self)
        button_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        
        self.load_button = ttk.Button(button_frame, text="View Selected Scan", command=self.load_selected_scan)
        self.load_button.pack(side=tk.LEFT, padx=5)
        
        self.compare_button = ttk.Button(button_frame, text="Compare Scans", command=self.compare_scans)
        self.compare_button.pack(side=tk.LEFT, padx=5)
        
        self.refresh_button = ttk.Button(button_frame, text="Refresh", command=self.load_history)
        self.refresh_button.pack(side=tk.RIGHT, padx=5)
        
        # Load scan history
        self.load_history()
    
    def load_history(self):
        """Load and display scan history."""
        # Clear the treeview
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
            
        # Get previous scans
        scan_ids = self.scanner.get_previous_scans()
        
        # Load and display each scan
        for scan_id in scan_ids:
            scan_result = self.scanner.load_scan_result(scan_id)
            if scan_result:
                # Format timestamp
                timestamp = scan_result.timestamp
                date_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                
                # Add to treeview
                self.history_tree.insert(
                    "", "end",
                    values=(
                        date_str,
                        scan_result.check_count,
                        scan_result.passed_count,
                        scan_result.failed_count,
                        f"{scan_result.duration:.2f}s"
                    ),
                    tags=(scan_id,)
                )
    
    def load_selected_scan(self):
        """Load and display the selected scan."""
        # Get selected item
        selection = self.history_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a scan to view.")
            return
            
        item = selection[0]
        tags = self.history_tree.item(item, "tags")
        scan_id = tags[0] if tags else None
        
        if not scan_id:
            return
            
        # Show scan details
        scan_result = self.scanner.load_scan_result(scan_id)
        if scan_result:
            # Create a new window to display the scan details
            ScanDetailWindow(self, scan_result)
    
    def compare_scans(self):
        """Compare two selected scans."""
        # Get selected items
        selection = self.history_tree.selection()
        if len(selection) != 2:
            messagebox.showwarning("Selection Error", "Please select exactly two scans to compare.")
            return
            
        # Get scan IDs
        item1, item2 = selection
        tags1 = self.history_tree.item(item1, "tags")
        tags2 = self.history_tree.item(item2, "tags")
        
        scan_id1 = tags1[0] if tags1 else None
        scan_id2 = tags2[0] if tags2 else None
        
        if not scan_id1 or not scan_id2:
            return
            
        # Determine which scan is newer
        scan1 = self.scanner.load_scan_result(scan_id1)
        scan2 = self.scanner.load_scan_result(scan_id2)
        
        if scan1.timestamp > scan2.timestamp:
            new_scan_id, old_scan_id = scan_id1, scan_id2
        else:
            new_scan_id, old_scan_id = scan_id2, scan_id1
            
        # Compare scans
        comparison = self.scanner.compare_scans(old_scan_id, new_scan_id)
        
        # Show comparison results
        ComparisonWindow(self, comparison, old_scan_id, new_scan_id)


class SettingsTab(ttk.Frame):
    """Tab for application settings."""
    
    def __init__(self, parent, root_dir: str):
        super().__init__(parent)
        self.root_dir = root_dir
        self.settings = self.load_settings()
        self.init_ui()
        
    def init_ui(self):
        """Initialize the UI components."""
        # Main frame layout
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        
        # Create a frame for settings categories
        settings_frame = ttk.LabelFrame(self, text="Settings")
        settings_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Create a notebook for settings categories
        settings_notebook = ttk.Notebook(settings_frame)
        settings_notebook.pack(fill="both", expand=True)
        
        # Create general settings tab
        general_tab = ttk.Frame(settings_notebook)
        settings_notebook.add(general_tab, text="General")
        self.create_general_settings(general_tab)
        
        # Create scanning settings tab
        scanning_tab = ttk.Frame(settings_notebook)
        settings_notebook.add(scanning_tab, text="Scanning")
        self.create_scanning_settings(scanning_tab)
        
        # Create API settings tab
        api_tab = ttk.Frame(settings_notebook)
        settings_notebook.add(api_tab, text="API Integration")
        self.create_api_settings(api_tab)
        
        # Add save button
        button_frame = ttk.Frame(self)
        button_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        
        save_button = ttk.Button(button_frame, text="Save Settings", command=self.save_settings)
        save_button.pack(side=tk.RIGHT, padx=5)
        
    def create_general_settings(self, parent):
        """Create general settings UI."""
        # Create a frame for the settings
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add report directory setting
        ttk.Label(frame, text="Report Directory:").grid(row=0, column=0, sticky="w", pady=5)
        
        self.report_dir_var = tk.StringVar(value=self.settings.get("report_dir", os.path.join(self.root_dir, "reports")))
        report_dir_entry = ttk.Entry(frame, textvariable=self.report_dir_var, width=40)
        report_dir_entry.grid(row=0, column=1, sticky="ew", pady=5)
        
        browse_button = ttk.Button(frame, text="Browse...", command=self.browse_report_dir)
        browse_button.grid(row=0, column=2, padx=5, pady=5)
        
        # Add theme setting
        ttk.Label(frame, text="Theme:").grid(row=1, column=0, sticky="w", pady=5)
        
        self.theme_var = tk.StringVar(value=self.settings.get("theme", "default"))
        themes = ["default", "clam", "alt", "vista"]
        theme_combo = ttk.Combobox(frame, textvariable=self.theme_var, values=themes, state="readonly")
        theme_combo.grid(row=1, column=1, sticky="ew", pady=5)
        
        def on_theme_change(event):
            new_theme = self.theme_var.get()
            try:
                ttk.Style().theme_use(new_theme)
                # Update and save settings immediately
                self.settings["theme"] = new_theme
                self.save_settings(self.settings)
            except Exception as e:
                messagebox.showerror("Theme Error", f"Failed to apply theme: {str(e)}")

        theme_combo.bind("<<ComboboxSelected>>", on_theme_change)

        
        # Add auto-save setting
        ttk.Label(frame, text="Auto-save Settings:").grid(row=2, column=0, sticky="w", pady=5)
        
        self.autosave_var = tk.BooleanVar(value=self.settings.get("autosave", True))
        autosave_check = ttk.Checkbutton(frame, variable=self.autosave_var)
        autosave_check.grid(row=2, column=1, sticky="w", pady=5)
        
    def on_theme_change(event):
        try:
            ttk.Style().theme_use(self.theme_var.get())
        except Exception as e:
            messagebox.showerror("Theme Error", f"Failed to apply theme: {str(e)}")

        theme_combo.bind("<<ComboboxSelected>>", on_theme_change)

        
    def create_scanning_settings(self, parent):
        """Create scanning settings UI."""
        # Create a frame for the settings
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add thread count setting
        ttk.Label(frame, text="Worker Threads:").grid(row=0, column=0, sticky="w", pady=5)
        
        self.threads_var = tk.IntVar(value=self.settings.get("threads", 4))
        threads_spinbox = ttk.Spinbox(frame, from_=1, to=16, textvariable=self.threads_var, width=5)
        threads_spinbox.grid(row=0, column=1, sticky="w", pady=5)
        
        # Add timeout setting
        ttk.Label(frame, text="Connection Timeout (seconds):").grid(row=1, column=0, sticky="w", pady=5)
        
        self.timeout_var = tk.IntVar(value=self.settings.get("timeout", 30))
        timeout_spinbox = ttk.Spinbox(frame, from_=5, to=120, textvariable=self.timeout_var, width=5)
        timeout_spinbox.grid(row=1, column=1, sticky="w", pady=5)
        
        # Add auto-remediate setting
        ttk.Label(frame, text="Prompt for Remediation:").grid(row=2, column=0, sticky="w", pady=5)
        
        self.auto_remediate_var = tk.BooleanVar(value=self.settings.get("prompt_remediation", True))
        auto_remediate_check = ttk.Checkbutton(frame, variable=self.auto_remediate_var)
        auto_remediate_check.grid(row=2, column=1, sticky="w", pady=5)
    
    def create_api_settings(self, parent):
        """Create API integration settings UI."""
        # Create a frame for the settings
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add NVD API key setting
        ttk.Label(frame, text="NVD API Key:").grid(row=0, column=0, sticky="w", pady=5)
        
        self.nvd_api_key_var = tk.StringVar(value=self.settings.get("nvd_api_key", ""))
        nvd_api_key_entry = ttk.Entry(frame, textvariable=self.nvd_api_key_var, width=40, show="*")
        nvd_api_key_entry.grid(row=0, column=1, sticky="ew", pady=5)
        
        # Add show/hide toggle for API key
        self.show_key_var = tk.BooleanVar(value=False)
        
        def toggle_show_key():
            if self.show_key_var.get():
                nvd_api_key_entry.config(show="")
            else:
                nvd_api_key_entry.config(show="*")
                
        show_key_check = ttk.Checkbutton(frame, text="Show Key", variable=self.show_key_var, command=toggle_show_key)
        show_key_check.grid(row=0, column=2, padx=5, pady=5)
        
        # Add NVD API rate limit setting
        ttk.Label(frame, text="API Rate Limit (requests/min):").grid(row=1, column=0, sticky="w", pady=5)
        
        self.rate_limit_var = tk.IntVar(value=self.settings.get("rate_limit", 30))
        rate_limit_spinbox = ttk.Spinbox(frame, from_=1, to=100, textvariable=self.rate_limit_var, width=5)
        rate_limit_spinbox.grid(row=1, column=1, sticky="w", pady=5)
        
        # Add API timeout setting
        ttk.Label(frame, text="API Timeout (seconds):").grid(row=2, column=0, sticky="w", pady=5)
        
        self.api_timeout_var = tk.IntVar(value=self.settings.get("api_timeout", 10))
        api_timeout_spinbox = ttk.Spinbox(frame, from_=1, to=60, textvariable=self.api_timeout_var, width=5)
        api_timeout_spinbox.grid(row=2, column=1, sticky="w", pady=5)
        
        # Add test connection button
        test_button = ttk.Button(frame, text="Test Connection", command=self.test_api_connection)
        test_button.grid(row=3, column=1, sticky="w", pady=10)
        
    def browse_report_dir(self):
        """Open directory browser for report directory selection."""
        directory = filedialog.askdirectory(initialdir=self.report_dir_var.get())
        if directory:
            self.report_dir_var.set(directory)
            
    def test_api_connection(self):
        """Test the connection to the NVD API."""
        api_key = self.nvd_api_key_var.get()
        
        # Create a temporary NVD client
        from integrations.nvd_client import NVDClient
        client = NVDClient(api_key=api_key)
        
        try:
            result = client.test_connection()
            if result:
                messagebox.showinfo("Connection Test", "Successfully connected to NVD API.")
            else:
                messagebox.showerror("Connection Test", "Failed to connect to NVD API.")
        except Exception as e:
            messagebox.showerror("Connection Test", f"Error: {str(e)}")
            
    def load_settings(self):
        """Load settings from file."""
        settings_file = os.path.join(self.root_dir, "settings.json")
        if os.path.exists(settings_file):
            try:
                with open(settings_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading settings: {e}")
        return {}
        
    def save_settings(self, settings=None):
        """Save settings to file."""
        # Collect settings from UI
        if settings is None:
            settings = {
                "report_dir": self.report_dir_var.get(),
                "theme": self.theme_var.get(),
                "autosave": self.autosave_var.get(),
                "threads": self.threads_var.get(),
                "timeout": self.timeout_var.get(),
                "prompt_remediation": self.auto_remediate_var.get(),
                "nvd_api_key": self.nvd_api_key_var.get(),
                "rate_limit": self.rate_limit_var.get(),
                "api_timeout": self.api_timeout_var.get()
            }
        
        # Save settings to file
        settings_file = os.path.join(self.root_dir, "settings.json")
        try:
            with open(settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
            messagebox.showinfo("Settings", "Settings saved successfully.")
        except Exception as e:
            messagebox.showerror("Settings", f"Error saving settings: {str(e)}")
        
        # Apply the theme immediately
        try:
            ttk.Style().theme_use(self.theme_var.get())
        except Exception as e:
            messagebox.showerror("Theme Error", f"Failed to apply theme: {str(e)}")

class AboutTab(ttk.Frame):
    """Tab for application information."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.init_ui()
        
    def init_ui(self):
        """Initialize the UI components."""
        # Main frame layout
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        
        # Create a frame for the about information
        about_frame = ttk.Frame(self)
        about_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        
        # Add application logo/icon (placeholder)
        logo_label = ttk.Label(about_frame, text="🔒", font=("TkDefaultFont", 48))
        logo_label.pack(pady=10)
        
        # Add application name
        name_label = ttk.Label(about_frame, text="Security Auditor Tool", font=("TkDefaultFont", 16, "bold"))
        name_label.pack(pady=5)
        
        # Add version
        version_label = ttk.Label(about_frame, text="Version 1.0.0")
        version_label.pack()
        
        # Add description
        desc_text = tk.Text(about_frame, wrap=tk.WORD, height=6, width=50)
        desc_text.pack(pady=10, fill="x")
        desc_text.insert(tk.END, 
            "A lightweight, cross-platform security configuration auditing tool. "
            "This application helps identify and remediate security vulnerabilities "
            "in your system configuration on both Windows and Linux platforms, "
            "with direct integration to the NIST National Vulnerability Database."
        )
        desc_text.config(state="disabled")
        
        # Add features list
        features_frame = ttk.LabelFrame(about_frame, text="Features")
        features_frame.pack(pady=10, fill="x")
        
        features = [
            "Cross-platform support for Windows and Linux",
            "Plugin-based architecture for extensibility",
            "Integration with NIST NVD for CVE mapping",
            "Automatic remediation scripts",
            "Detailed reporting and scan history"
        ]
        
        for i, feature in enumerate(features):
            ttk.Label(features_frame, text=f"• {feature}").pack(anchor="w", padx=10, pady=2)
        
        # Add links
        links_frame = ttk.Frame(about_frame)
        links_frame.pack(pady=10)
        
        # These would be hyperlinks in a real application
        github_link = ttk.Label(links_frame, text="GitHub Repository", foreground="blue", cursor="hand2")
        github_link.pack(side=tk.LEFT, padx=10)
        
        docs_link = ttk.Label(links_frame, text="Documentation", foreground="blue", cursor="hand2")
        docs_link.pack(side=tk.LEFT, padx=10)
        
        report_link = ttk.Label(links_frame, text="Report Issues", foreground="blue", cursor="hand2")
        report_link.pack(side=tk.LEFT, padx=10)


class RemediationDialog(tk.Toplevel):
    """Dialog for confirming remediation."""
    
    def __init__(self, parent, check_id: str, script: str):
        super().__init__(parent)
        self.title("Confirm Remediation")
        self.geometry("600x500")
        self.transient(parent)
        self.grab_set()
        
        self.check_id = check_id
        self.script = script
        self.confirmed = False
        
        self.init_ui()
        
    def init_ui(self):
        """Initialize the UI components."""
        # Add warning label
        warning_label = ttk.Label(
            self, 
            text="Please review the remediation script carefully before proceeding.",
            font=("TkDefaultFont", 10, "bold")
        )
        warning_label.pack(padx=10, pady=10)
        
        # Add script display
        script_frame = ttk.LabelFrame(self, text="Remediation Script")
        script_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        script_text = tk.Text(script_frame, wrap=tk.WORD)
        script_text.pack(side=tk.LEFT, fill="both", expand=True)
        
        script_scrollbar = ttk.Scrollbar(script_frame, orient="vertical", command=script_text.yview)
        script_text.configure(yscrollcommand=script_scrollbar.set)
        script_scrollbar.pack(side=tk.RIGHT, fill="y")
        
        # Insert script content
        script_text.insert(tk.END, self.script)
        script_text.config(state="disabled")
        
        # Add disclaimer
        disclaimer_label = ttk.Label(
            self, 
            text="This action will make changes to your system configuration.\nMake sure you understand the consequences.",
            foreground="red"
        )
        disclaimer_label.pack(padx=10, pady=5)
        
        # Add buttons
        button_frame = ttk.Frame(self)
        button_frame.pack(fill="x", padx=10, pady=10)
        
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.cancel)
        cancel_button.pack(side=tk.RIGHT, padx=5)
        
        confirm_button = ttk.Button(button_frame, text="Apply Remediation", command=self.confirm)
        confirm_button.pack(side=tk.RIGHT, padx=5)
        
    def confirm(self):
        """Confirm remediation."""
        self.confirmed = True
        self.destroy()
        
    def cancel(self):
        """Cancel remediation."""
        self.confirmed = False
        self.destroy()


class ExportDialog(tk.Toplevel):
    """Dialog for selecting export format."""
    
    def __init__(self, parent, formats: List[str]):
        super().__init__(parent)
        self.title("Export Format")
        self.geometry("300x200")
        self.transient(parent)
        self.grab_set()
        
        self.formats = formats
        self.selected_format = None
        
        self.init_ui()
        
    def init_ui(self):
        """Initialize the UI components."""
        # Add label
        label = ttk.Label(self, text="Select export format:")
        label.pack(padx=10, pady=10)
        
        # Add format radio buttons
        self.format_var = tk.StringVar(value=self.formats[0])
        
        for format_name in self.formats:
            radio = ttk.Radiobutton(
                self,
                text=format_name,
                variable=self.format_var,
                value=format_name
            )
            radio.pack(anchor="w", padx=20, pady=2)
            
        # Add buttons
        button_frame = ttk.Frame(self)
        button_frame.pack(fill="x", padx=10, pady=10)
        
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.cancel)
        cancel_button.pack(side=tk.RIGHT, padx=5)
        
        confirm_button = ttk.Button(button_frame, text="Export", command=self.confirm)
        confirm_button.pack(side=tk.RIGHT, padx=5)
        
    def confirm(self):
        """Confirm format selection."""
        self.selected_format = self.format_var.get()
        self.destroy()
        
    def cancel(self):
        """Cancel export."""
        self.selected_format = None
        self.destroy()


class ScanDetailWindow(tk.Toplevel):
    """Window for displaying detailed scan results."""
    
    def __init__(self, parent, scan_result):
        super().__init__(parent)
        self.title(f"Scan Details - {scan_result.scan_id}")
        self.geometry("900x700")
        
        self.scan_result = scan_result
        self.init_ui()
        
    def init_ui(self):
        """Initialize the UI components."""
        # Add summary frame
        summary_frame = ttk.LabelFrame(self, text="Scan Summary")
        summary_frame.pack(fill="x", padx=10, pady=5)
        
        # Add summary info
        summary_grid = ttk.Frame(summary_frame)
        summary_grid.pack(padx=10, pady=5)
        
        # Add scan ID
        ttk.Label(summary_grid, text="Scan ID:").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Label(summary_grid, text=self.scan_result.scan_id).grid(row=0, column=1, sticky="w", pady=2)
        
        # Add timestamp
        ttk.Label(summary_grid, text="Date:").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Label(summary_grid, text=self.scan_result.timestamp.strftime("%Y-%m-%d %H:%M:%S")).grid(row=1, column=1, sticky="w", pady=2)
        
        # Add duration
        ttk.Label(summary_grid, text="Duration:").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Label(summary_grid, text=f"{self.scan_result.duration:.2f} seconds").grid(row=2, column=1, sticky="w", pady=2)
        
        # Add check counts
        ttk.Label(summary_grid, text="Total Checks:").grid(row=0, column=2, sticky="w", padx=20, pady=2)
        ttk.Label(summary_grid, text=str(self.scan_result.check_count)).grid(row=0, column=3, sticky="w", pady=2)
        
        ttk.Label(summary_grid, text="Passed:").grid(row=1, column=2, sticky="w", padx=20, pady=2)
        ttk.Label(summary_grid, text=str(self.scan_result.passed_count)).grid(row=1, column=3, sticky="w", pady=2)
        
        ttk.Label(summary_grid, text="Failed:").grid(row=2, column=2, sticky="w", padx=20, pady=2)
        ttk.Label(summary_grid, text=str(self.scan_result.failed_count)).grid(row=2, column=3, sticky="w", pady=2)
        
        # Add results treeview
        results_frame = ttk.LabelFrame(self, text="Check Results")
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Create a treeview for the results
        columns = ("Status", "Check ID", "Title", "Severity")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        
        # Define headings
        for col in columns:
            self.results_tree.heading(col, text=col)
            
        # Set column widths
        self.results_tree.column("Status", width=80, anchor="center")
        self.results_tree.column("Check ID", width=150)
        self.results_tree.column("Title", width=400)
        self.results_tree.column("Severity", width=80, anchor="center")
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        # Add treeview and scrollbar to frame
        self.results_tree.pack(side=tk.LEFT, fill="both", expand=True)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        
        # Add detail frame
        detail_frame = ttk.LabelFrame(self, text="Check Details")
        detail_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Add text widget for details
        self.detail_text = tk.Text(detail_frame, wrap=tk.WORD)
        self.detail_text.pack(side=tk.LEFT, fill="both", expand=True)
        
        detail_scrollbar = ttk.Scrollbar(detail_frame, orient="vertical", command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=detail_scrollbar.set)
        detail_scrollbar.pack(side=tk.RIGHT, fill="y")
        
        # Add button frame
        button_frame = ttk.Frame(self)
        button_frame.pack(fill="x", padx=10, pady=10)
        
        close_button = ttk.Button(button_frame, text="Close", command=self.destroy)
        close_button.pack(side=tk.RIGHT, padx=5)
        
        export_button = ttk.Button(button_frame, text="Export Results", command=self.export_results)
        export_button.pack(side=tk.RIGHT, padx=5)
        
        # Populate the results treeview
        self.populate_results()
        
        # Bind treeview selection
        self.results_tree.bind("<<TreeviewSelect>>", self.on_result_selected)
        
    def populate_results(self):
        """Populate the results treeview."""
        for check_id, result in self.scan_result.results.items():
            passed = result.get("passed", False)
            status = "✅" if passed else "❌"
            title = result.get("title", check_id)
            severity = result.get("severity", "").capitalize()
            
            self.results_tree.insert("", "end", values=(status, check_id, title, severity), tags=(check_id,))
    
    def on_result_selected(self, event):
        """Handle selection of a result item."""
        # Get selected item
        selection = self.results_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        tags = self.results_tree.item(item, "tags")
        check_id = tags[0] if tags else None
        
        if not check_id:
            return
            
        # Get the result
        result = self.scan_result.results.get(check_id)
        if not result:
            return
            
        # Display details
        self.detail_text.delete(1.0, tk.END)
        
        # Add basic info
        self.detail_text.insert(tk.END, f"Check ID: {check_id}\n")
        self.detail_text.insert(tk.END, f"Title: {result.get('title', '')}\n")
        self.detail_text.insert(tk.END, f"Description: {result.get('description', '')}\n")
        self.detail_text.insert(tk.END, f"Severity: {result.get('severity', '').capitalize()}\n")
        self.detail_text.insert(tk.END, f"Status: {'Passed' if result.get('passed', False) else 'Failed'}\n\n")
        
        # Add details
        self.detail_text.insert(tk.END, "Details:\n")
        details = result.get("details", {})
        for key, value in details.items():
            self.detail_text.insert(tk.END, f"- {key}: {value}\n")
            
        # Add CVEs
        cve_ids = result.get("cve_ids", [])
        if cve_ids:
            self.detail_text.insert(tk.END, "\nAssociated CVEs:\n")
            for cve_id in cve_ids:
                self.detail_text.insert(tk.END, f"- {cve_id}\n")
    
    def export_results(self):
        """Export scan results."""
        # Ask for export format
        formats = ["HTML", "Text", "JSON"]
        dialog = ExportDialog(self, formats)
        self.wait_window(dialog)
        
        if not dialog.selected_format:
            return
            
        # Ask for file location
        extensions = {
            "HTML": ".html",
            "Text": ".txt",
            "JSON": ".json"
        }
        
        ext = extensions.get(dialog.selected_format, ".txt")
        filename = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[(f"{dialog.selected_format} Files", f"*{ext}"), ("All Files", "*.*")],
            initialfile=f"security_scan_{self.scan_result.scan_id}{ext}"
        )
        
        if not filename:
            return
            
        # Export the results
        try:
            from utils.export import ExportManager
            export_manager = ExportManager()
            export_manager.export_scan(self.scan_result.scan_id, filename, dialog.selected_format.lower())
            messagebox.showinfo("Export Successful", f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))


class ComparisonWindow(tk.Toplevel):
    """Window for displaying scan comparison results."""
    
    def __init__(self, parent, comparison: dict, old_scan_id: str, new_scan_id: str):
        super().__init__(parent)
        self.title("Scan Comparison")
        self.geometry("800x600")
        
        self.comparison = comparison
        self.old_scan_id = old_scan_id
        self.new_scan_id = new_scan_id
        self.init_ui()
        
    def init_ui(self):
        """Initialize the UI components."""
        # Add header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(
            header_frame, 
            text=f"Comparing {self.old_scan_id} → {self.new_scan_id}",
            font=("TkDefaultFont", 12, "bold")
        ).pack()
        
        # Create notebook for different comparisons
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Create tabs for different comparison categories
        improved_tab = ttk.Frame(notebook)
        notebook.add(improved_tab, text=f"Improved ({len(self.comparison.get('improved', []))})")
        self.create_check_list(improved_tab, self.comparison.get("improved", []), "improved")
        
        regressed_tab = ttk.Frame(notebook)
        notebook.add(regressed_tab, text=f"Regressed ({len(self.comparison.get('regressed', []))})")
        self.create_check_list(regressed_tab, self.comparison.get("regressed", []), "regressed")
        
        fixed_tab = ttk.Frame(notebook)
        notebook.add(fixed_tab, text=f"Fixed ({len(self.comparison.get('fixed', []))})")
        self.create_check_list(fixed_tab, self.comparison.get("fixed", []), "fixed")
        
        new_issues_tab = ttk.Frame(notebook)
        notebook.add(new_issues_tab, text=f"New Issues ({len(self.comparison.get('new_issues', []))})")
        self.create_check_list(new_issues_tab, self.comparison.get("new_issues", []), "new_issues")
        
        # Add button frame
        button_frame = ttk.Frame(self)
        button_frame.pack(fill="x", padx=10, pady=10)
        
        close_button = ttk.Button(button_frame, text="Close", command=self.destroy)
        close_button.pack(side=tk.RIGHT, padx=5)
        
        export_button = ttk.Button(button_frame, text="Export Comparison", command=self.export_comparison)
        export_button.pack(side=tk.RIGHT, padx=5)
        
    def create_check_list(self, parent, check_ids: list, category: str):
        """Create a list of checks in a tab."""
        if not check_ids:
            ttk.Label(parent, text="No changes in this category").pack(padx=20, pady=20)
            return
            
        # Create a treeview
        columns = ("Check ID", "Title", "Severity")
        tree = ttk.Treeview(parent, columns=columns, show="headings")
        
        # Define headings
        for col in columns:
            tree.heading(col, text=col)
            
        # Set column widths
        tree.column("Check ID", width=150)
        tree.column("Title", width=400)
        tree.column("Severity", width=80, anchor="center")
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Add treeview and scrollbar to frame
        tree.pack(side=tk.LEFT, fill="both", expand=True)
        scrollbar.pack(side=tk.RIGHT, fill="y")
        
        # Load scan results to get check details
        from core.scanner import Scanner
        scanner = self.master.scanner  # Assuming the parent has a scanner attribute
        
        old_scan = scanner.load_scan_result(self.old_scan_id)
        new_scan = scanner.load_scan_result(self.new_scan_id)
        
        # Populate the treeview
        for check_id in check_ids:
            # Get check details from the appropriate scan result
            if category in ["improved", "regressed"]:
                # Check exists in both scans
                check_result = new_scan.results.get(check_id, {})
            elif category == "fixed":
                # New check that passes
                check_result = new_scan.results.get(check_id, {})
            else:  # new_issues
                # New check that fails
                check_result = new_scan.results.get(check_id, {})
                
            title = check_result.get("title", check_id)
            severity = check_result.get("severity", "").capitalize()
            
            tree.insert("", "end", values=(check_id, title, severity))
            
    def export_comparison(self):
        """Export comparison results."""
        # Ask for file location
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            initialfile=f"comparison_{self.old_scan_id}_to_{self.new_scan_id}.txt"
        )
        
        if not filename:
            return
            
        # Export the comparison
        try:
            with open(filename, 'w') as f:
                f.write(f"Comparison: {self.old_scan_id} → {self.new_scan_id}\n\n")
                
                f.write(f"Improved ({len(self.comparison.get('improved', []))}):\n")
                for check_id in self.comparison.get("improved", []):
                    f.write(f"- {check_id}\n")
                f.write("\n")
                
                f.write(f"Regressed ({len(self.comparison.get('regressed', []))}):\n")
                for check_id in self.comparison.get("regressed", []):
                    f.write(f"- {check_id}\n")
                f.write("\n")
                
                f.write(f"Fixed ({len(self.comparison.get('fixed', []))}):\n")
                for check_id in self.comparison.get("fixed", []):
                    f.write(f"- {check_id}\n")
                f.write("\n")
                
                f.write(f"New Issues ({len(self.comparison.get('new_issues', []))}):\n")
                for check_id in self.comparison.get("new_issues", []):
                    f.write(f"- {check_id}\n")
                
            messagebox.showinfo("Export Successful", f"Comparison exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))


class MainApplication(ttk.Frame):
    """Main application window."""
    
    def __init__(self, parent, root_dir: str, platform_info: dict):
        super().__init__(parent)
        self.parent = parent
        self.root_dir = root_dir
        self.platform_info = platform_info
        
        # Setup scanner
        plugin_dirs = [
            os.path.join(root_dir, "plugins"),
            os.path.join(root_dir, "plugins", "windows"),
            os.path.join(root_dir, "plugins", "linux")
        ]
        report_dir = os.path.join(root_dir, "reports")
        self.scanner = Scanner(plugin_dirs, report_dir)
        
        # Initialize UI
        self.init_ui()
        
    def init_ui(self):
        """Initialize the UI components."""
        # Create a notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)
        
        # Create scan tab
        self.scan_tab = ScanTab(self.notebook, self.scanner, self.platform_info)
        self.notebook.add(self.scan_tab, text="Scan System")
        
         # Create history tab
        self.history_tab = HistoryTab(self.notebook, self.scanner)
        self.notebook.add(self.history_tab, text="Scan History")

        # Create settings tab
        self.settings_tab = SettingsTab(self.notebook, self.root_dir)
        self.notebook.add(self.settings_tab, text="Settings")

        # Create about tab
        self.about_tab = AboutTab(self.notebook)
        self.notebook.add(self.about_tab, text="About")

        # Pack the main frame
        self.pack(fill="both", expand=True)

        # Apply saved theme
        self.apply_theme()

    def apply_theme(self):
        """Apply saved theme from settings."""
        try:
            import json
            settings_path = os.path.join(self.root_dir, "settings.json")
            if os.path.exists(settings_path):
                with open(settings_path, "r") as f:
                    settings = json.load(f)
                theme = settings.get("theme", "default")
                ttk.Style().theme_use(theme)
        except Exception as e:
            print(f"[Warning] Failed to apply theme: {e}")


def run_gui():
    """Entry point to launch the Tkinter GUI."""
    root = tk.Tk()
    root.title("Security Auditor Tool")
    root.geometry("1024x768")
    root.minsize(800, 600)

    # Platform detection
    platform_info = get_platform_info()

    # Root directory
    root_dir = os.path.dirname(os.path.abspath(__file__))

    # Set application icon if available
    icon_path = os.path.join(root_dir, "assets", "icon.ico")
    if os.path.exists(icon_path):
        try:
            root.iconbitmap(icon_path)
        except Exception as e:
            print(f"[Warning] Failed to set window icon: {e}")

    # Launch main app
    app = MainApplication(root, root_dir, platform_info)
    app.mainloop()
