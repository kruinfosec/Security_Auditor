#!/usr/bin/env python3
# Remediation execution framework

import os
import tempfile
import subprocess
import platform
import logging
from typing import List, Dict, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("remediation")

class RemediationExecutor:
    """Handles execution of remediation scripts."""
    
    def __init__(self):
        """Initialize the remediation executor."""
        self.system = platform.system().lower()
    
    def execute_script(self, script_content: str, admin_required: bool = False) -> Dict[str, Any]:
        """
        Execute a remediation script.
        
        Args:
            script_content: The script content (bash or PowerShell)
            admin_required: Whether administrator/root privileges are required
            
        Returns:
            dict: The execution result
        """
        if not script_content.strip():
            return {
                "success": False,
                "message": "Empty script content"
            }
            
        # Create a temporary script file
        with tempfile.NamedTemporaryFile(delete=False, suffix=self._get_script_extension()) as script_file:
            script_path = script_file.name
            script_file.write(script_content.encode('utf-8'))
            
        try:
            # Execute the script based on the operating system
            if self.system == 'windows':
                return self._execute_powershell(script_path, admin_required)
            else:  # Linux or macOS
                return self._execute_bash(script_path, admin_required)
        finally:
            # Clean up the temporary file
            try:
                os.unlink(script_path)
            except:
                pass
    
    def _get_script_extension(self) -> str:
        """Get the appropriate script file extension for the current OS."""
        return '.ps1' if self.system == 'windows' else '.sh'
    
    def _execute_powershell(self, script_path: str, admin_required: bool) -> Dict[str, Any]:
        """Execute a PowerShell script on Windows."""
        try:
            cmd = ['powershell', '-ExecutionPolicy', 'Bypass', '-File', script_path]
            
            if admin_required:
                # Check if running as admin
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    return {
                        "success": False,
                        "message": "Administrator privileges required",
                        "requires_elevation": True
                    }
            
            # Execute the script
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            
            return {
                "success": process.returncode == 0,
                "stdout": stdout,
                "stderr": stderr,
                "return_code": process.returncode
            }
        except Exception as e:
            logger.error(f"Error executing PowerShell script: {e}")
            return {
                "success": False,
                "message": str(e)
            }