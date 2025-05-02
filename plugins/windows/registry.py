#!/usr/bin/env python3
# Windows Registry security check plugin

import os
import re
import sys
import subprocess
import winreg
from typing import List, Dict, Any, Tuple, Optional
from integrations.nvd_client import NVDClient

from core.plugin_loader import SecurityCheck

class RegistryCheck(SecurityCheck):
    """Check Windows Registry for security misconfigurations."""
    
    CHECK_ID = "windows.registry"
    TITLE = "Windows Registry Security Check"
    DESCRIPTION = "Checks Windows Registry settings for security best practices and misconfigurations"
    PLATFORM = "windows"
    SEVERITY = "high"
    
    # Registry paths and expected values for security settings
    SECURITY_SETTINGS = [
        # User Account Control settings
        {
            "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "key": "EnableLUA",
            "expected": 1,
            "name": "User Account Control",
            "description": "User Account Control (UAC) helps prevent unauthorized changes to your computer",
            "severity": "high"
        },
        {
            "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "key": "ConsentPromptBehaviorAdmin",
            "expected": 2,
            "name": "UAC Prompt Behavior for Administrators",
            "description": "Controls how UAC prompts administrators for consent",
            "severity": "medium"
        },
        # Windows Update settings
        {
            "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update",
            "key": "AUOptions",
            "expected": 4,
            "name": "Windows Automatic Updates",
            "description": "Controls how Windows receives automatic updates",
            "severity": "high"
        },
        # Remote Desktop settings
        {
            "path": r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "key": "fDenyTSConnections",
            "expected": 1,  # 1 means Remote Desktop is disabled
            "name": "Remote Desktop Connections",
            "description": "Controls whether Remote Desktop connections are allowed",
            "severity": "medium"
        },
        # Network security settings
        {
            "path": r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "key": "RestrictNullSessAccess",
            "expected": 1,
            "name": "Restrict Anonymous Access",
            "description": "Controls whether anonymous users can access shared resources",
            "severity": "high"
        },
        # Auto-run settings
        {
            "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "key": "NoDriveTypeAutoRun",
            "expected": 255,  # Disable autorun for all drives
            "name": "AutoRun Settings",
            "description": "Controls whether autorun is enabled for removable media",
            "severity": "medium"
        },
        # Windows Defender settings
        {
            "path": r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
            "key": "DisableRealtimeMonitoring",
            "expected": 0,  # 0 means real-time protection is enabled
            "name": "Windows Defender Real-time Protection",
            "description": "Controls whether Windows Defender real-time protection is enabled",
            "severity": "critical"
        },
        # Password policy - Minimum password length
        {
            "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Network",
            "key": "MinPwdLen",
            "expected": 8,  # Minimum password length of 8 characters
            "expected_min": 8,  # For values where higher is more secure
            "name": "Minimum Password Length",
            "description": "Controls the minimum length for passwords",
            "severity": "high"
        },
        # SMB Signing
        {
            "path": r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
            "key": "RequireSecuritySignature",
            "expected": 1,
            "name": "SMB Signing",
            "description": "Controls whether SMB signing is required",
            "severity": "medium"
        },
    ]
    
    def __init__(self):
        """Initialize the Windows Registry check."""
        super().__init__()
        self.issues = []
        self.registry_values = {}
        self.total_settings_checked = 0
        self.nvd = NVDClient()

        
    def check(self) -> bool:
        """
        Check Windows Registry security settings.
        
        Returns:
            bool: True if all checks pass, False otherwise
        """
        # Verify we're running on Windows
        if sys.platform != 'win32':
            self.details = {
                "message": "This check only runs on Windows systems",
                "issues": [],
                "registry_values": {}
            }
            return True
            
        # Check each registry setting
        for setting in self.SECURITY_SETTINGS:
            self.total_settings_checked += 1
            self._check_registry_setting(setting)
            
        # Store check details
        self.details = {
            "message": f"Found {len(self.issues)} security issues in Windows Registry" if self.issues else "Windows Registry security settings are correctly configured",
            "issues": self.issues,
            "registry_values": self.registry_values,
            "total_settings_checked": self.total_settings_checked
        }
        
        # Add CVE references for known vulnerabilities related to registry misconfigurations
        # Build keyword list for CVE mapping
        keywords = [f"{issue['name']} {issue.get('description', '')}" for issue in self.issues]

        # Map to CVEs
        try:
            issues_payload = {
                self.CHECK_ID: {
                    "passed": False,
                    "title": self.TITLE,
                    "description": self.DESCRIPTION,
                    "cve_ids": self.cve_ids  # likely still empty
                }
            }

            cve_mappings = self.nvd.map_security_issues_to_cves(issues_payload)
            self.cve_ids = [cve["id"] for cve in cve_mappings.get(self.CHECK_ID, [])]
            self.details["cve_ids"] = self.cve_ids
            self.details["cve_info"] = cve_mappings.get(self.CHECK_ID, [])


            self.cve_details = cve_mappings.get(self.CHECK_ID, [])  # Optional: used for export or display
            
        except Exception as e:
            self.details["cve_error"] = f"Failed to fetch CVEs: {e}"

            
        # The check passes if there are no issues
        return len(self.issues) == 0
    
    
        
    def _check_registry_setting(self, setting: Dict[str, Any]):
        """
        Check a specific registry setting.
        
        Args:
            setting: Dictionary containing registry path, key, and expected value
        """
        try:
            # Determine registry root key
            if setting["path"].startswith("SOFTWARE") or setting["path"].startswith("SYSTEM"):
                root_key = winreg.HKEY_LOCAL_MACHINE
                full_path = setting["path"]
            else:
                # Default to HKLM
                root_key = winreg.HKEY_LOCAL_MACHINE
                full_path = setting["path"]
                
            # Try to open the registry key
            try:
                reg_key = winreg.OpenKey(root_key, full_path, 0, winreg.KEY_READ)
            except FileNotFoundError:
                # Registry path doesn't exist
                self.issues.append({
                    "name": setting["name"],
                    "path": full_path,
                    "key": setting["key"],
                    "issue": "Registry path does not exist",
                    "recommendation": f"Create registry path {full_path} and set {setting['key']} to {setting['expected']}",
                    "severity": setting["severity"]
                })
                return
                
            # Try to read the registry value
            try:
                value, value_type = winreg.QueryValueEx(reg_key, setting["key"])
                
                # Store the current value
                self.registry_values[f"{full_path}\\{setting['key']}"] = {
                    "current_value": value,
                    "expected_value": setting["expected"],
                    "value_type": value_type
                }
                
                # Check if the value matches the expected value
                if "expected_min" in setting:
                    # For values where higher is more secure (like minimum password length)
                    if value < setting["expected_min"]:
                        self.issues.append({
                            "name": setting["name"],
                            "path": full_path,
                            "key": setting["key"],
                            "current_value": value,
                            "expected_value": f"At least {setting['expected_min']}",
                            "issue": f"{setting['description']} is set too low",
                            "recommendation": f"Set {setting['key']} to at least {setting['expected_min']}",
                            "severity": setting["severity"]
                        })
                elif value != setting["expected"]:
                    self.issues.append({
                        "name": setting["name"],
                        "path": full_path,
                        "key": setting["key"],
                        "current_value": value,
                        "expected_value": setting["expected"],
                        "issue": f"{setting['description']} is not configured correctly",
                        "recommendation": f"Set {setting['key']} to {setting['expected']}",
                        "severity": setting["severity"]
                    })
            except FileNotFoundError:
                # Registry value doesn't exist
                self.issues.append({
                    "name": setting["name"],
                    "path": full_path,
                    "key": setting["key"],
                    "issue": f"Registry value {setting['key']} does not exist",
                    "recommendation": f"Create registry value {setting['key']} and set it to {setting['expected']}",
                    "severity": setting["severity"]
                })
            finally:
                winreg.CloseKey(reg_key)
        except Exception as e:
            # Error checking registry setting
            self.issues.append({
                "name": setting["name"],
                "path": setting["path"],
                "key": setting["key"],
                "issue": f"Error checking registry setting: {str(e)}",
                "recommendation": "Ensure the registry key exists and is accessible",
                "severity": setting["severity"]
            })
            
    def remediate(self) -> bool:
        """
        Apply automatic remediation for registry security issues.
        
        Returns:
            bool: True if remediation was successful, False otherwise
        """
        # Check if running with administrative privileges
        if not self._is_admin():
            self.details = {"error": "Administrative privileges required for registry remediation"}
            return False
            
        success = True
        remediated_settings = []
        
        # Apply remediation for each issue
        for issue in self.issues:
            try:
                path = issue["path"]
                key = issue["key"]
                
                # Determine expected value
                if "expected_value" in issue:
                    if isinstance(issue["expected_value"], str) and issue["expected_value"].startswith("At least "):
                        # For minimum values, use the minimum value
                        value = int(issue["expected_value"].replace("At least ", ""))
                    else:
                        value = issue["expected_value"]
                else:
                    # Find the expected value from the settings
                    for setting in self.SECURITY_SETTINGS:
                        if setting["path"] == path and setting["key"] == key:
                            value = setting["expected"]
                            break
                    else:
                        continue
                        
                # Determine registry root key
                if path.startswith("SOFTWARE") or path.startswith("SYSTEM"):
                    root_key = winreg.HKEY_LOCAL_MACHINE
                else:
                    # Default to HKLM
                    root_key = winreg.HKEY_LOCAL_MACHINE
                    
                # Open or create the registry key
                reg_key = winreg.CreateKeyEx(root_key, path, 0, winreg.KEY_WRITE)
                
                # Determine value type
                if isinstance(value, int):
                    value_type = winreg.REG_DWORD
                else:
                    value_type = winreg.REG_SZ
                    
                # Set the registry value
                winreg.SetValueEx(reg_key, key, 0, value_type, value)
                winreg.CloseKey(reg_key)
                
                remediated_settings.append({
                    "path": path,
                    "key": key,
                    "value": value
                })
            except Exception as e:
                success = False
                self.details = {"error": f"Failed to remediate {path}\\{key}: {str(e)}"}
                
        self.details = {
            "message": "Registry remediation completed",
            "remediated_settings": remediated_settings,
            "success": success
        }
        
        return success
        
    def _is_admin(self) -> bool:
        """Check if the script is running with administrative privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
            
    def get_remediation_script(self) -> str:
        """
        Get a PowerShell script for remediating registry security issues.
        
        Returns:
            str: PowerShell script content
        """
        script = [
            "# Windows Registry Security Remediation Script",
            "# This script applies security best practices to Windows Registry settings",
            "",
            "# Check if running with administrative privileges",
            "if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] \"Administrator\")) {",
            "    Write-Warning \"This script requires administrative privileges. Please run it as Administrator.\"",
            "    exit 1",
            "}",
            "",
            "Write-Host \"Applying secure Windows Registry settings...\" -ForegroundColor Green",
            "# Create a log file",
            "$logFile = \"$env:TEMP\\registry_remediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log\"",
            "Write-Host \"Logging remediation actions to $logFile\"",
            "",
            "function Write-Log {",
            "    param (",
            "        [string]$message",
            "    )",
            "    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'",
            "    \"[$timestamp] $message\" | Out-File -FilePath $logFile -Append",
            "    Write-Host $message",
            "}",
            "",
            "function Set-SecureRegistryValue {",
            "    param (",
            "        [string]$path,",
            "        [string]$key,",
            "        $value,",
            "        [string]$description",
            "    )",
            "",
            "    try {",
            "        # Check if the path exists, if not create it",
            "        if (!(Test-Path \"Registry::HKEY_LOCAL_MACHINE\\$path\")) {",
            "            Write-Log \"Creating registry path: HKLM:\\$path\"",
            "            New-Item -Path \"Registry::HKEY_LOCAL_MACHINE\\$path\" -Force | Out-Null",
            "        }",
            "",
            "        # Get the current value if it exists",
            "        $currentValue = $null",
            "        try {",
            "            $currentValue = Get-ItemProperty -Path \"Registry::HKEY_LOCAL_MACHINE\\$path\" -Name $key -ErrorAction Stop | Select-Object -ExpandProperty $key",
            "            Write-Log \"Current value of $path\\$key: $currentValue\"",
            "        } catch {",
            "            Write-Log \"Registry value does not exist yet: $path\\$key\"",
            "        }",
            "",
            "        # Set the new value",
            "        Set-ItemProperty -Path \"Registry::HKEY_LOCAL_MACHINE\\$path\" -Name $key -Value $value -Type DWord -Force",
            "        $newValue = Get-ItemProperty -Path \"Registry::HKEY_LOCAL_MACHINE\\$path\" -Name $key | Select-Object -ExpandProperty $key",
            "",
            "        Write-Log \"Updated registry value $path\\$key: $currentValue -> $newValue ($description)\"",
            "        return $true",
            "    } catch {",
            "        Write-Log \"ERROR: Failed to set registry value $path\\$key to $value: $_\"",
            "        return $false",
            "    }",
            "}",
            "",
            "# Track remediation results",
            "$totalSettings = 0",
            "$successfulSettings = 0",
            "",
            "# User Account Control settings",
            "$totalSettings++",
            "if (Set-SecureRegistryValue -path \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" -key \"EnableLUA\" -value 1 -description \"Enable User Account Control\") {",
            "    $successfulSettings++",
            "}",
            "",
            "$totalSettings++",
            "if (Set-SecureRegistryValue -path \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" -key \"ConsentPromptBehaviorAdmin\" -value 2 -description \"UAC Prompt Behavior for Administrators\") {",
            "    $successfulSettings++",
            "}",
            "",
            "# Windows Update settings",
            "$totalSettings++",
            "if (Set-SecureRegistryValue -path \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\" -key \"AUOptions\" -value 4 -description \"Windows Automatic Updates\") {",
            "    $successfulSettings++",
            "}",
            "",
            "# Remote Desktop settings",
            "$totalSettings++",
            "if (Set-SecureRegistryValue -path \"SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" -key \"fDenyTSConnections\" -value 1 -description \"Disable Remote Desktop Connections\") {",
            "    $successfulSettings++",
            "}",
            "",
            "# Network security settings",
            "$totalSettings++",
            "if (Set-SecureRegistryValue -path \"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" -key \"RestrictNullSessAccess\" -value 1 -description \"Restrict Anonymous Access\") {",
            "    $successfulSettings++",
            "}",
            "",
            "# Auto-run settings",
            "$totalSettings++",
            "if (Set-SecureRegistryValue -path \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" -key \"NoDriveTypeAutoRun\" -value 255 -description \"Disable AutoRun for all drives\") {",
            "    $successfulSettings++",
            "}",
            "",
            "# Windows Defender settings",
            "$totalSettings++",
            "if (Set-SecureRegistryValue -path \"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\" -key \"DisableRealtimeMonitoring\" -value 0 -description \"Enable Windows Defender Real-time Protection\") {",
            "    $successfulSettings++",
            "}",
            "",
            "# Password policy - Minimum password length",
            "$totalSettings++",
            "if (Set-SecureRegistryValue -path \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Network\" -key \"MinPwdLen\" -value 8 -description \"Minimum Password Length\") {",
            "    $successfulSettings++",
            "}",
            "",
            "# SMB Signing",
            "$totalSettings++",
            "if (Set-SecureRegistryValue -path \"SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\" -key \"RequireSecuritySignature\" -value 1 -description \"Require SMB signing\") {",
            "    $successfulSettings++",
            "}",
            "",
            "# Final summary",
            "Write-Host \"Registry remediation complete!\" -ForegroundColor Green",
            "Write-Log \"Successfully remediated $successfulSettings out of $totalSettings settings\"",
            "Write-Host \"Log file saved to: $logFile\"",
            "",
            "# Return success status",
            "if ($successfulSettings -eq $totalSettings) {",
            "    Write-Host \"All settings were updated successfully.\" -ForegroundColor Green",
            "    exit 0",
            "} else {",
            "    Write-Host \"Some settings could not be updated. Check the log file for details.\" -ForegroundColor Yellow",
            "    exit 1",
            "}"
        ]
        
        return "\n".join(script)

# Import ctypes for admin check that was referenced but not imported in the original code
import ctypes