#!/usr/bin/env python3
# Security Auditor Tool - Main Entry Point

import sys
import os
import tkinter as tk
from gui.main_window import MainApplication
from utils.system import get_platform_info

def setup_environment():
    """Set up necessary environment variables and paths."""
    # Add the project root to the path
    root_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, root_dir)
    
    # Create necessary directories if they don't exist
    os.makedirs(os.path.join(root_dir, "reports"), exist_ok=True)
    os.makedirs(os.path.join(root_dir, "logs"), exist_ok=True)
    
    return root_dir

def main():
    """Main entry point for the Security Auditor Tool."""
    # Setup environment
    root_dir = setup_environment()
    
    # Get platform info
    platform_info = get_platform_info()
    print(f"Running on {platform_info['os']} {platform_info['version']}")
    
    # Initialize Tkinter
    root = tk.Tk()
    root.title("Security Auditor Tool")
    root.geometry("1200x800")
    
    # Initialize and pack the main application window
    app = MainApplication(root, root_dir, platform_info)
    app.pack(fill="both", expand=True)
    
    # Start the main event loop
    root.mainloop()

if __name__ == "__main__":
    main()
