"""
Reusable UI components for the security auditing tool.
These components are designed to be used across different parts of the application.
"""
import tkinter as tk
from tkinter import ttk, font
import os
from PIL import Image, ImageTk


class ScrollableFrame(ttk.Frame):
    """A scrollable frame widget"""
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.canvas = tk.Canvas(self)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Bind mousewheel to scroll
        self.bind_mousewheel()

    def bind_mousewheel(self):
        """Bind mousewheel to scrolling"""
        def _on_mousewheel(event):
            self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        self.canvas.bind_all("<MouseWheel>", _on_mousewheel)

    def unbind_mousewheel(self):
        """Unbind mousewheel from scrolling"""
        self.canvas.unbind_all("<MouseWheel>")


class StatusBar(ttk.Frame):
    """Status bar widget for displaying application status"""
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.progress_var = tk.DoubleVar()
        self.progress_var.set(0.0)
        
        self.status_label = ttk.Label(self, textvariable=self.status_var, anchor=tk.W)
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.progress_bar.pack(side=tk.RIGHT, padx=5)
    
    def set_status(self, text):
        """Set status text"""
        self.status_var.set(text)
        self.update_idletasks()
    
    def set_progress(self, value):
        """Set progress bar value (0-100)"""
        self.progress_var.set(value)
        self.update_idletasks()


class SecurityCheckItem(ttk.Frame):
    """Widget for displaying a security check and its status"""
    def __init__(self, parent, check_id, title, description, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.check_id = check_id
        self.remediation_command = None
        self.remediation_callback = None
        
        # Configure styles
        style = ttk.Style()
        style.configure("Pass.TLabel", foreground="green")
        style.configure("Fail.TLabel", foreground="red")
        style.configure("Warning.TLabel", foreground="orange")
        
        # Main frame layout
        self.title_label = ttk.Label(self, text=title, font=("TkDefaultFont", 10, "bold"))
        self.description_label = ttk.Label(self, text=description, wraplength=400)
        self.status_label = ttk.Label(self, text="Not checked")
        self.fix_button = ttk.Button(self, text="Fix", state=tk.DISABLED, command=self._fix_issue)
        self.details_button = ttk.Button(self, text="Details", command=self._show_details)
        
        # Layout widgets
        self.title_label.grid(row=0, column=0, sticky="w", padx=5)
        self.status_label.grid(row=0, column=1, sticky="e", padx=5)
        self.description_label.grid(row=1, column=0, columnspan=1, sticky="w", padx=5, pady=2)
        self.fix_button.grid(row=1, column=1, sticky="e", padx=2)
        self.details_button.grid(row=1, column=2, sticky="e", padx=2)
        
        # Separator for visual distinction
        ttk.Separator(self, orient='horizontal').grid(row=2, column=0, columnspan=3, sticky="ew", pady=5)
        
        # Data storage
        self.details = {}
        self.cve_data = None
    
    def set_status(self, status, details=None):
        """Set the check status and update the UI accordingly"""
        if status.lower() == "pass":
            self.status_label.config(text="PASS", style="Pass.TLabel")
            self.fix_button.config(state=tk.DISABLED)
        elif status.lower() == "fail":
            self.status_label.config(text="FAIL", style="Fail.TLabel")
            self.fix_button.config(state=tk.NORMAL)
        elif status.lower() == "warning":
            self.status_label.config(text="WARNING", style="Warning.TLabel")
            self.fix_button.config(state=tk.NORMAL)
        else:
            self.status_label.config(text=status)
            
        if details:
            self.details = details
            
    def set_remediation(self, command, callback=None):
        """Set the remediation command and callback"""
        self.remediation_command = command
        self.remediation_callback = callback
        if command:
            self.fix_button.config(state=tk.NORMAL)
        
    def set_cve_data(self, cve_data):
        """Set associated CVE data"""
        self.cve_data = cve_data
    
    def _fix_issue(self):
        """Execute the remediation command"""
        if self.remediation_command and self.remediation_callback:
            result = self.remediation_callback(self.check_id, self.remediation_command)
            if result.get('success', False):
                self.set_status("pass")
    
    def _show_details(self):
        """Show details about the check and possible CVEs"""
        details_window = tk.Toplevel(self)
        details_window.title(f"Details: {self.title_label['text']}")
        details_window.geometry("600x400")
        
        # Create notebook with tabs
        notebook = ttk.Notebook(details_window)
        
        # Check details tab
        details_frame = ttk.Frame(notebook)
        details_text = tk.Text(details_frame, wrap=tk.WORD, height=15, width=70)
        details_text.insert(tk.END, f"Check ID: {self.check_id}\n\n")
        
        for key, value in self.details.items():
            details_text.insert(tk.END, f"{key}: {value}\n")
            
        if self.remediation_command:
            details_text.insert(tk.END, f"\nRemediation Command:\n{self.remediation_command}\n")
            
        details_text.config(state=tk.DISABLED)
        details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # CVE tab if available
        if self.cve_data:
            cve_frame = ttk.Frame(notebook)
            cve_text = tk.Text(cve_frame, wrap=tk.WORD, height=15, width=70)
            
            for cve in self.cve_data:
                cve_text.insert(tk.END, f"CVE ID: {cve.get('id', 'Unknown')}\n")
                cve_text.insert(tk.END, f"Severity: {cve.get('severity', 'Unknown')}\n")
                cve_text.insert(tk.END, f"Description: {cve.get('description', 'No description available')}\n")
                cve_text.insert(tk.END, f"References: {', '.join(cve.get('references', []))}\n\n")
                
            cve_text.config(state=tk.DISABLED)
            cve_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            notebook.add(cve_frame, text="CVE Information")
        
        notebook.add(details_frame, text="Check Details")
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)


class ConfirmDialog(tk.Toplevel):
    """Custom dialog for confirming actions"""
    def __init__(self, parent, title, message, command_preview=None):
        super().__init__(parent)
        self.title(title)
        self.result = False
        
        # Make dialog modal
        self.transient(parent)
        self.grab_set()
        
        # Dialog content
        frame = ttk.Frame(self, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text=message, wraplength=400).pack(pady=10)
        
        if command_preview:
            command_frame = ttk.LabelFrame(frame, text="Command to be executed")
            command_text = tk.Text(command_frame, height=5, width=60, wrap=tk.WORD)
            command_text.insert(tk.END, command_preview)
            command_text.config(state=tk.DISABLED)
            command_text.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
            command_frame.pack(pady=10, fill=tk.BOTH, expand=True)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Cancel", command=self._cancel).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Confirm", command=self._confirm).pack(side=tk.RIGHT, padx=5)
        
        # Center the dialog
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
        
        # Wait for interaction
        self.wait_window(self)
    
    def _confirm(self):
        self.result = True
        self.destroy()
    
    def _cancel(self):
        self.result = False
        self.destroy()


class SummaryPanel(ttk.Frame):
    """Summary panel for displaying scan results"""
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        
        # Summary counts
        self.pass_count = tk.IntVar(value=0)
        self.fail_count = tk.IntVar(value=0)
        self.warning_count = tk.IntVar(value=0)
        
        # Create widgets
        summary_title = ttk.Label(self, text="Scan Summary", font=("TkDefaultFont", 12, "bold"))
        
        counts_frame = ttk.Frame(self)
        ttk.Label(counts_frame, text="Pass:", font=("TkDefaultFont", 10, "bold"), foreground="green").grid(row=0, column=0, sticky="w", padx=5)
        ttk.Label(counts_frame, textvariable=self.pass_count).grid(row=0, column=1, sticky="w")
        
        ttk.Label(counts_frame, text="Fail:", font=("TkDefaultFont", 10, "bold"), foreground="red").grid(row=1, column=0, sticky="w", padx=5)
        ttk.Label(counts_frame, textvariable=self.fail_count).grid(row=1, column=1, sticky="w")
        
        ttk.Label(counts_frame, text="Warning:", font=("TkDefaultFont", 10, "bold"), foreground="orange").grid(row=2, column=0, sticky="w", padx=5)
        ttk.Label(counts_frame, textvariable=self.warning_count).grid(row=2, column=1, sticky="w")
        
        # Pack widgets
        summary_title.pack(anchor="w", pady=(0, 5))
        counts_frame.pack(fill="x", pady=5)
        ttk.Separator(self, orient='horizontal').pack(fill="x", pady=10)
    
    def update_counts(self, pass_count, fail_count, warning_count):
        """Update the summary counts"""
        self.pass_count.set(pass_count)
        self.fail_count.set(fail_count)
        self.warning_count.set(warning_count)
