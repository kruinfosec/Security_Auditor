#!/usr/bin/env python3
# SSH configuration security check plugin

import os
import re
import subprocess
from typing import List, Dict, Any
from integrations.nvd_client import NVDClient

from core.plugin_loader import SecurityCheck

class SSHConfigCheck(SecurityCheck):
    """Check for secure SSH configuration settings."""
    
    CHECK_ID = "linux.ssh_config"
    TITLE = "SSH Server Configuration Security Check"
    DESCRIPTION = "Checks SSH server configuration for security best practices"
    PLATFORM = "linux"
    SEVERITY = "high"
    
    # SSH config file path
    SSH_CONFIG_PATH = "/etc/ssh/sshd_config"
    
    # Security recommendations for SSH
    SECURE_SETTINGS = {
        "PermitRootLogin": "no",
        "PasswordAuthentication": "no",
        "PermitEmptyPasswords": "no",
        "ChallengeResponseAuthentication": "no",
        "KerberosAuthentication": "no",
        "GSSAPIAuthentication": "no",
        "X11Forwarding": "no",
        "HostbasedAuthentication": "no",
        "PermitUserEnvironment": "no",
        "Protocol": "2",
        "LogLevel": "VERBOSE",
        "MaxAuthTries": "4",
        "ClientAliveInterval": "300",
        "ClientAliveCountMax": "0"
    }
    
    # Setting priorities (for reporting)
    PRIORITY_MAP = {
        "PermitRootLogin": "critical",
        "PasswordAuthentication": "high",
        "PermitEmptyPasswords": "critical",
        "Protocol": "critical",
    }
    
    def __init__(self):
        """Initialize the SSH config check."""
        super().__init__()
        self.config_values = {}
        self.issues = []
        self.nvd = NVDClient()
        
    def check(self) -> bool:
        """
        Check SSH configuration for security issues.
        
        Returns:
            bool: True if all checks pass, False otherwise
        """
        # Check if SSH is installed and running
        if not self._is_ssh_installed():
            self.details = {
                "message": "SSH server is not installed or not detected",
                "issues": [],
                "config_path": self.SSH_CONFIG_PATH
            }
            # Not considering this a failure, since SSH might be intentionally not installed
            return True
            
        # Parse SSH config
        self._parse_ssh_config()
        
        # Check for security issues
        self._check_security_settings()
        
        # Store the check details
        self.details = {
            "message": f"Found {len(self.issues)} security issues in SSH configuration" if self.issues else "SSH configuration is secure",
            "issues": self.issues,
            "config_path": self.SSH_CONFIG_PATH,
            "config_values": self.config_values
        }
        
        # Link to CVEs for SSH vulnerabilities
        self.cve_ids = []
        keywords = []
        for issue in self.issues:
            setting = issue.get("setting", "")
            description = issue.get("issue", "")
            if setting:
                keywords.append(f"SSH {setting} {description}")
        try:
            cve_data = self.nvd.map_security_issues_to_cves(keywords)
            self.cve_ids = [cve["id"] for cve in cve_data]
            self.details["cve_ids"] = self.cve_ids
            self.details["cve_info"] = cve_data
        except Exception as e:
            self.details["cve_error"] = str(e)
            
        # The check passes if there are no issues
        return len(self.issues) == 0
        
    def _is_ssh_installed(self) -> bool:
        """Check if SSH server is installed and running."""
        try:
            # Check if the sshd process is running
            result = subprocess.run(
                ["ps", "-ef"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if "sshd" in result.stdout:
                return True
                
            # Check if the SSH config file exists
            if os.path.exists(self.SSH_CONFIG_PATH):
                return True
                
            return False
        except Exception:
            return False
            
    def _parse_ssh_config(self):
        """Parse the SSH configuration file."""
        if not os.path.exists(self.SSH_CONFIG_PATH):
            return
            
        try:
            with open(self.SSH_CONFIG_PATH, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                        
                    # Parse key-value pairs
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        key, value = parts
                        self.config_values[key] = value
        except Exception as e:
            self.issues.append({
                "setting": "SSH Config File",
                "issue": f"Could not read SSH config file: {str(e)}",
                "recommendation": "Ensure the SSH config file is readable",
                "severity": "high"
            })
            
    def _check_security_settings(self):
        """Check SSH settings against security recommendations."""
        for setting, recommended_value in self.SECURE_SETTINGS.items():
            current_value = self.config_values.get(setting)
            
            # If the setting is missing, it might use a default value
            if current_value is None:
                # For settings where the default might be insecure
                if setting in ["PermitRootLogin", "PasswordAuthentication", "X11Forwarding"]:
                    self.issues.append({
                        "setting": setting,
                        "issue": f"Setting not explicitly configured (may use insecure default)",
                        "recommendation": f"Add '{setting} {recommended_value}' to SSH config",
                        "severity": self.PRIORITY_MAP.get(setting, "medium")
                    })
                continue
                
            # Check if the current value matches the recommendation
            # For numeric values, we check if the current setting is less secure
            if setting in ["MaxAuthTries", "ClientAliveInterval"]:
                try:
                    if int(current_value) > int(recommended_value):
                        self.issues.append({
                            "setting": setting,
                            "issue": f"Value too high: {current_value} (recommended: ≤ {recommended_value})",
                            "recommendation": f"Set '{setting} {recommended_value}' or lower",
                            "severity": self.PRIORITY_MAP.get(setting, "medium")
                        })
                except ValueError:
                    self.issues.append({
                        "setting": setting,
                        "issue": f"Invalid value: {current_value}",
                        "recommendation": f"Set '{setting} {recommended_value}'",
                        "severity": self.PRIORITY_MAP.get(setting, "medium")
                    })
            elif current_value != recommended_value:
                self.issues.append({
                    "setting": setting,
                    "issue": f"Insecure value: {current_value} (recommended: {recommended_value})",
                    "recommendation": f"Set '{setting} {recommended_value}'",
                    "severity": self.PRIORITY_MAP.get(setting, "medium")
                })
                
    def remediate(self) -> bool:
        """
        Apply automatic remediation for SSH configuration issues.
        
        Returns:
            bool: True if remediation was successful, False otherwise
        """
        # Check if running as root (required for modifying SSH config)
        if os.geteuid() != 0:
            self.details = {"error": "Root privileges required for SSH config remediation"}
            return False
            
        # Backup the original config file
        backup_path = f"{self.SSH_CONFIG_PATH}.bak"
        try:
            with open(self.SSH_CONFIG_PATH, 'r') as src:
                with open(backup_path, 'w') as dst:
                    dst.write(src.read())
        except Exception as e:
            self.details = {"error": f"Failed to backup SSH config: {str(e)}"}
            return False
            
        # Read the existing config
        try:
            with open(self.SSH_CONFIG_PATH, 'r') as f:
                config_lines = f.readlines()
        except Exception as e:
            self.details = {"error": f"Failed to read SSH config: {str(e)}"}
            return False
            
        # Apply the secure settings
        modified_config = self._apply_secure_settings(config_lines)
        
        # Write the modified config
        try:
            with open(self.SSH_CONFIG_PATH, 'w') as f:
                f.write(modified_config)
                
            # Restart the SSH service
            subprocess.run(["systemctl", "restart", "sshd"], check=True)
            
            self.details = {
                "message": "SSH configuration updated successfully",
                "backup_file": backup_path
            }
            return True
        except Exception as e:
            self.details = {"error": f"Failed to update SSH config: {str(e)}"}
            # Try to restore the backup
            try:
                with open(backup_path, 'r') as src:
                    with open(self.SSH_CONFIG_PATH, 'w') as dst:
                        dst.write(src.read())
            except:
                pass
            return False
            
    def _apply_secure_settings(self, config_lines: List[str]) -> str:
        """
        Apply secure settings to the SSH config.
        
        Args:
            config_lines: The current config file as lines
            
        Returns:
            str: The modified config content
        """
        # Track which settings have been applied
        applied_settings = set()
        
        # Create a new config with updated settings
        new_config_lines = []
        for line in config_lines:
            modified_line = line
            
            # Look for settings to modify
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#'):
                new_config_lines.append(line)
                continue
                
            # Check if this line contains a setting we want to modify
            for setting, recommended_value in self.SECURE_SETTINGS.items():
                if line_stripped.startswith(setting + " "):
                    modified_line = f"{setting} {recommended_value}\n"
                    applied_settings.add(setting)
                    break
                    
            new_config_lines.append(modified_line)
            
        # Add any settings that weren't in the original config
        for setting, recommended_value in self.SECURE_SETTINGS.items():
            if setting not in applied_settings:
                new_config_lines.append(f"{setting} {recommended_value}\n")
                
        return "".join(new_config_lines)
        
    def get_remediation_script(self) -> str:
        """
        Get a bash script for remediating SSH configuration issues.
        
        Returns:
            str: Bash script content
        """
        script = [
            "#!/bin/bash",
            "# SSH Configuration Security Remediation Script",
            "# This script applies security best practices to the SSH server configuration",
            "",
            "# Check if running as root",
            "if [ \"$(id -u)\" -ne 0 ]; then",
            "    echo \"This script must be run as root\" >&2",
            "    exit 1",
            "fi",
            "",
            "CONFIG_FILE=\"/etc/ssh/sshd_config\"",
            "BACKUP_FILE=\"${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)\"",
            "",
            "# Check if SSH config exists",
            "if [ ! -f \"$CONFIG_FILE\" ]; then",
            "    echo \"SSH config file not found: $CONFIG_FILE\" >&2",
            "    exit 1",
            "fi",
            "",
            "# Create a backup of the original config",
            "echo \"Creating backup of SSH config at $BACKUP_FILE\"",
            "cp \"$CONFIG_FILE\" \"$BACKUP_FILE\"",
            "if [ $? -ne 0 ]; then",
            "    echo \"Failed to create backup file\" >&2",
            "    exit 1",
            "fi",
            "",
            "echo \"Applying secure SSH configuration settings...\"",
            ""
        ]
        
        # Add commands to update each setting
        for setting, value in self.SECURE_SETTINGS.items():
            script.append(f"# Set {setting} to {value}")
            script.append(f"if grep -q \"^{setting} \" \"$CONFIG_FILE\"; then")
            script.append(f"    # Setting exists, update it")
            script.append(f"    sed -i \"s/^{setting} .*/{setting} {value}/\" \"$CONFIG_FILE\"")
            script.append(f"elif grep -q \"^#{setting} \" \"$CONFIG_FILE\"; then")
            script.append(f"    # Setting is commented out, uncomment and update")
            script.append(f"    sed -i \"s/^#{setting} .*/{setting} {value}/\" \"$CONFIG_FILE\"")
            script.append(f"else")
            script.append(f"    # Setting doesn't exist, add it")
            script.append(f"    echo \"{setting} {value}\" >> \"$CONFIG_FILE\"")
            script.append(f"fi")
            script.append("")
        
        script.extend([
            "echo \"Configuration updated successfully.\"",
            "",
            "# Restart SSH service",
            "if command -v systemctl >/dev/null 2>&1; then",
            "    echo \"Restarting SSH service...\"",
            "    systemctl restart sshd",
            "elif command -v service >/dev/null 2>&1; then",
            "    echo \"Restarting SSH service...\"",
            "    service sshd restart",
            "else",
            "    echo \"Unable to restart SSH service automatically.\"",
            "    echo \"Please restart the SSH service manually.\"",
            "fi",
            "",
            "echo \"SSH configuration hardening complete!\"",
            "echo \"Original configuration backed up at: $BACKUP_FILE\"",
            "exit 0"
        ])
        
        return "\n".join(script)