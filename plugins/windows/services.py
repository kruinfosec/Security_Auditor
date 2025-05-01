#!/usr/bin/env python3
# Windows Services security check plugin

import os
import sys
import subprocess
from typing import List, Dict, Any, Optional

from core.plugin_loader import SecurityCheck

class WindowsServicesCheck(SecurityCheck):
    """Check Windows Services for security misconfigurations."""
    
    CHECK_ID = "windows.services"
    TITLE = "Windows Services Security Check"
    DESCRIPTION = "Checks Windows services for security misconfigurations and unnecessary running services"
    PLATFORM = "windows"
    SEVERITY = "high"
    
    # List of potentially dangerous services that should be disabled
    # Each entry contains:
    # - name: The service name
    # - display_name: Human-readable display name
    # - recommendation: "disable" or "manual" or "automatic"
    # - description: Description of the security risk
    # - severity: Severity of the risk
    SERVICES_TO_CHECK = [
        {
            "name": "RemoteRegistry",
            "display_name": "Remote Registry",
            "recommendation": "disable",
            "description": "Allows remote users to modify registry settings",
            "severity": "high"
        },
        {
            "name": "TelnetServer",
            "display_name": "Telnet Server",
            "recommendation": "disable",
            "description": "Transmits credentials in plaintext",
            "severity": "critical"
        },
        {
            "name": "ftpsvc",
            "display_name": "FTP Server",
            "recommendation": "disable",
            "description": "FTP transmits credentials in cleartext",
            "severity": "high"
        },
        {
            "name": "SNMPTRAP",
            "display_name": "SNMP Trap",
            "recommendation": "disable",
            "description": "May expose system information if not needed",
            "severity": "medium"
        },
        {
            "name": "SSDPSRV",
            "display_name": "SSDP Discovery",
            "recommendation": "disable",
            "description": "Can be used for network discovery and attack surface",
            "severity": "medium"
        },
        {
            "name": "upnphost",
            "display_name": "UPnP Device Host",
            "recommendation": "disable",
            "description": "Can be used for network discovery and attack surface",
            "severity": "medium"
        },
        {
            "name": "WinRM",
            "display_name": "Windows Remote Management (WS-Management)",
            "recommendation": "manual",
            "description": "Remote management service that should be secured",
            "severity": "high"
        },
        {
            "name": "WMSvc",
            "display_name": "Web Management Service",
            "recommendation": "disable",
            "description": "Remote web server management service",
            "severity": "high"
        },
        {
            "name": "TapiSrv",
            "display_name": "Telephony",
            "recommendation": "disable",
            "description": "Legacy service rarely needed on modern systems",
            "severity": "low"
        },
        {
            "name": "SharedAccess",
            "display_name": "Internet Connection Sharing (ICS)",
            "recommendation": "disable",
            "description": "Can create unexpected network routes if enabled",
            "severity": "medium"
        }
    ]
    
    def __init__(self):
        """Initialize the Windows Services check."""
        super().__init__()
        self.issues = []
        self.service_statuses = {}
        
    def check(self) -> bool:
        """
        Check Windows services configurations for security issues.
        
        Returns:
            bool: True if all checks pass, False otherwise
        """
        # Verify we're running on Windows
        if sys.platform != 'win32':
            self.details = {
                "message": "This check only runs on Windows systems",
                "issues": [],
                "service_statuses": {}
            }
            return True
            
        # Get the status of all relevant services
        self._check_services()
        
        # Store check details
        self.details = {
            "message": f"Found {len(self.issues)} security issues with Windows services" if self.issues else "No issues found with Windows service configurations",
            "issues": self.issues,
            "service_statuses": self.service_statuses,
        }
        
        # Add CVE references for known vulnerabilities related to insecure services
        if any(issue["name"] == "Telnet Server" for issue in self.issues):
            self.cve_ids.append("CVE-2020-0796")  # Example CVE related to Windows services
            
        if any(issue["name"] == "Remote Registry" for issue in self.issues):
            self.cve_ids.append("CVE-2019-1315")  # Example CVE related to Remote Registry
            
        # The check passes if there are no issues
        return len(self.issues) == 0
        
    def _check_services(self):
        """Check the configuration of Windows services."""
        # Use PowerShell to get service information
        command = [
            "powershell", 
            "-Command", 
            "Get-Service | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json"
        ]
        
        try:
            # Execute the PowerShell command
            process = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            
            # Parse the JSON output
            import json
            services = json.loads(process.stdout)
            
            # If only one service is returned, convert to list
            if not isinstance(services, list):
                services = [services]
                
            # Check each service of interest
            for service_to_check in self.SERVICES_TO_CHECK:
                service_name = service_to_check["name"]
                
                # Find the service in the list
                service_found = False
                for service in services:
                    if service["Name"].lower() == service_name.lower():
                        service_found = True
                        service_status = service["Status"]
                        service_start_type = service["StartType"]
                        
                        # Store the service status
                        self.service_statuses[service_name] = {
                            "display_name": service["DisplayName"],
                            "status": service_status,
                            "start_type": service_start_type
                        }
                        
                        # Check if the service is properly configured
                        if service_to_check["recommendation"] == "disable":
                            if service_start_type.lower() != "disabled":
                                self.issues.append({
                                    "name": service_to_check["display_name"],
                                    "service_name": service_name,
                                    "current_status": service_status,
                                    "current_start_type": service_start_type,
                                    "recommended_start_type": "Disabled",
                                    "issue": f"{service_to_check['display_name']} service is not disabled",
                                    "description": service_to_check["description"],
                                    "recommendation": f"Disable the {service_to_check['display_name']} service",
                                    "severity": service_to_check["severity"]
                                })
                        elif service_to_check["recommendation"] == "manual":
                            if service_start_type.lower() not in ["manual", "disabled"]:
                                self.issues.append({
                                    "name": service_to_check["display_name"],
                                    "service_name": service_name,
                                    "current_status": service_status,
                                    "current_start_type": service_start_type,
                                    "recommended_start_type": "Manual",
                                    "issue": f"{service_to_check['display_name']} service is set to start automatically",
                                    "description": service_to_check["description"],
                                    "recommendation": f"Set the {service_to_check['display_name']} service to Manual start",
                                    "severity": service_to_check["severity"]
                                })
                        break
                                
                # If the service was not found, it might not be installed
                if not service_found:
                    self.service_statuses[service_name] = {
                        "display_name": service_to_check["display_name"],
                        "status": "Not Installed",
                        "start_type": "N/A"
                    }
        except Exception as e:
            self.issues.append({
                "name": "Service Scan Error",
                "issue": f"Error checking services: {str(e)}",
                "recommendation": "Ensure PowerShell is available and the user has permissions to query services",
                "severity": "medium"
            })
            
    def remediate(self) -> bool:
        """
        Apply automatic remediation for Windows service issues.
        
        Returns:
            bool: True if remediation was successful, False otherwise
        """
        # Check if running with administrative privileges
        if not self._is_admin():
            self.details = {"error": "Administrative privileges required for service configuration"}
            return False
            
        success = True
        remediated_services = []
        
        for issue in self.issues:
            try:
                service_name = issue["service_name"]
                recommended_start_type = issue["recommended_start_type"].lower()
                
                # PowerShell command to set service start type
                if recommended_start_type == "disabled":
                    ps_command = f"Set-Service -Name '{service_name}' -StartupType Disabled"
                elif recommended_start_type == "manual":
                    ps_command = f"Set-Service -Name '{service_name}' -StartupType Manual"
                else:
                    continue  # Skip if not recognized
                    
                # Execute the PowerShell command
                process = subprocess.run(
                    ["powershell", "-Command", ps_command],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if process.returncode == 0:
                    # Also stop the service if it's running
                    if issue["current_status"].lower() == "running":
                        stop_command = f"Stop-Service -Name '{service_name}' -Force"
                        subprocess.run(
                            ["powershell", "-Command", stop_command],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )
                    
                    remediated_services.append({
                        "service_name": service_name,
                        "display_name": issue["name"],
                        "new_start_type": recommended_start_type
                    })
                else:
                    success = False
            except Exception as e:
                success = False
                self.details = {"error": f"Failed to remediate {service_name}: {str(e)}"}
                
        self.details = {
            "message": "Service remediation completed",
            "remediated_services": remediated_services,
            "success": success
        }
        
        return success
        
    def _is_admin(self) -> bool:
        """Check if the script is running with administrative privileges."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
            
    def get_remediation_script(self) -> str:
        """
        Get a PowerShell script for remediating Windows service issues.
        
        Returns:
            str: PowerShell script content
        """
        script = [
            "# Windows Services Security Remediation Script",
            "# This script applies security best practices to Windows service configurations",
            "",
            "# Check if running with administrative privileges",
            "if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] \"Administrator\")) {",
            "    Write-Warning \"This script requires administrative privileges. Please run it as Administrator.\"",
            "    exit 1",
            "}",
            "",
            "# Create a log file",
            "$logFile = \"$env:TEMP\\services_remediation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log\"",
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
            "function Set-SecureServiceConfig {",
            "    param (",
            "        [string]$serviceName,",
            "        [string]$displayName,",
            "        [string]$startupType,",
            "        [bool]$stopIfRunning = $true",
            "    )",
            "",
            "    try {",
            "        # Check if the service exists",
            "        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue",
            "        if ($null -eq $service) {",
            "            Write-Log \"Service not found: $serviceName ($displayName) - may not be installed\"",
            "            return $true",
            "        }",
            "",
            "        # Get current configuration",
            "        $currentStartType = (Get-Service -Name $serviceName).StartType",
            "        $currentStatus = (Get-Service -Name $serviceName).Status",
            "        Write-Log \"Current state of $displayName: StartType=$currentStartType, Status=$currentStatus\"",
            "",
            "        # Set the startup type",
            "        Set-Service -Name $serviceName -StartupType $startupType",
            "        $newStartType = (Get-Service -Name $serviceName).StartType",
            "        Write-Log \"Updated service $displayName startup type: $currentStartType -> $newStartType\"",
            "",
            "        # Stop the service if it's running and stopIfRunning is true",
            "        if ($stopIfRunning -and $currentStatus -eq 'Running') {",
            "            Write-Log \"Stopping service $displayName...\"",
            "            Stop-Service -Name $serviceName -Force",
            "            $newStatus = (Get-Service -Name $serviceName).Status",
            "            Write-Log \"Service $displayName is now $newStatus\"",
            "        }",
            "",
            "        return $true",
            "    } catch {",
            "        Write-Log \"ERROR: Failed to configure service $displayName: $_\"",
            "        return $false",
            "    }",
            "}",
            "",
            "# Track remediation results",
            "$totalServices = 0",
            "$successfulServices = 0",
            "",
            "Write-Host \"Applying secure Windows service configurations...\" -ForegroundColor Green",
            ""
        ]
        
        # Add service-specific remediation commands
        for service in self.SERVICES_TO_CHECK:
            display_name = service["display_name"]
            service_name = service["name"]
            recommendation = service["recommendation"]
            
            startup_type = "Disabled" if recommendation == "disable" else "Manual"
            
            script.append(f"# {display_name} ({service['description']})")
            script.append("$totalServices++")
            script.append(f"if (Set-SecureServiceConfig -serviceName \"{service_name}\" -displayName \"{display_name}\" -startupType \"{startup_type}\") {{")
            script.append("    $successfulServices++")
            script.append("}")
            script.append("")
        
        script.extend([
            "# Final summary",
            "Write-Host \"Service remediation complete!\" -ForegroundColor Green",
            "Write-Log \"Successfully remediated $successfulServices out of $totalServices services\"",
            "Write-Host \"Log file saved to: $logFile\"",
            "",
            "# Return success status",
            "if ($successfulServices -eq $totalServices) {",
            "    Write-Host \"All services were configured successfully.\" -ForegroundColor Green",
            "    exit 0",
            "} else {",
            "    Write-Host \"Some services could not be configured. Check the log file for details.\" -ForegroundColor Yellow",
            "    exit 1",
            "}"
        ])
        
        return "\n".join(script)
