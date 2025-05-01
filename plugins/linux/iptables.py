#!/usr/bin/env python3
# Iptables firewall security check plugin

import os
import re
import subprocess
from typing import List, Dict, Any, Optional

from core.plugin_loader import SecurityCheck

class IptablesCheck(SecurityCheck):
    """Check for proper iptables firewall configuration."""
    
    CHECK_ID = "linux.iptables"
    TITLE = "Linux Firewall Configuration Check"
    DESCRIPTION = "Checks for proper iptables firewall configuration and security best practices"
    PLATFORM = "linux"
    SEVERITY = "high"
    
    # Essential services to check for proper configuration
    ESSENTIAL_SERVICES = {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS"
    }
    
    # Potentially dangerous ports that should be restricted
    DANGEROUS_PORTS = {
        21: "FTP",
        23: "Telnet",
        3389: "RDP",
        5900: "VNC"
    }
    
    def __init__(self):
        """Initialize the iptables check."""
        super().__init__()
        self.iptables_installed = False
        self.firewalld_installed = False
        self.ufw_installed = False
        self.active_firewall = None
        self.rules = []
        self.issues = []
        
    def check(self) -> bool:
        """
        Check iptables configuration for security issues.
        
        Returns:
            bool: True if firewall is properly configured, False otherwise
        """
        # Check which firewall system is installed
        self._detect_firewall_system()
        
        if not self.active_firewall:
            self.issues.append({
                "issue": "No active firewall detected",
                "recommendation": "Install and configure a firewall (iptables, firewalld, or ufw)",
                "severity": "critical"
            })
            self.details = {
                "message": "No active firewall detected",
                "issues": self.issues,
                "rules": []
            }
            return False
            
        # Get firewall rules
        self._get_firewall_rules()
        
        # Analyze firewall configuration
        self._analyze_firewall_rules()
        
        # Store the check details
        self.details = {
            "message": f"Found {len(self.issues)} security issues in firewall configuration" if self.issues else "Firewall configuration appears secure",
            "issues": self.issues,
            "firewall": self.active_firewall,
            "rules": self.rules
        }
        
        # Link CVEs related to firewall misconfigurations
        if self.issues:
            # Example CVE for firewall misconfiguration
            self.cve_ids = ["CVE-2019-11510"]  # Example CVE related to improper network access controls
            
        # The check passes if there are no issues
        return len(self.issues) == 0
        
    def _detect_firewall_system(self):
        """Detect which firewall system is installed and active."""
        # Check iptables
        try:
            result = subprocess.run(
                ["iptables", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0:
                self.iptables_installed = True
                
                # Check if iptables has rules
                result = subprocess.run(
                    ["iptables", "-L"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                if "Chain INPUT" in result.stdout and not "Chain INPUT (policy ACCEPT)" in result.stdout:
                    self.active_firewall = "iptables"
        except:
            pass
            
        # Check firewalld
        try:
            result = subprocess.run(
                ["firewall-cmd", "--state"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0 and "running" in result.stdout:
                self.firewalld_installed = True
                self.active_firewall = "firewalld"
        except:
            pass
            
        # Check ufw
        try:
            result = subprocess.run(
                ["ufw", "status"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0 and "Status: active" in result.stdout:
                self.ufw_installed = True
                self.active_firewall = "ufw"
        except:
            pass
            
    def _get_firewall_rules(self):
        """Get the current firewall rules."""
        if self.active_firewall == "iptables":
            self._get_iptables_rules()
        elif self.active_firewall == "firewalld":
            self._get_firewalld_rules()
        elif self.active_firewall == "ufw":
            self._get_ufw_rules()
            
    def _get_iptables_rules(self):
        """Get iptables rules."""
        try:
            # Get IPv4 rules
            result = subprocess.run(
                ["iptables", "-L", "-n", "-v"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                self.rules.append({
                    "type": "iptables-ipv4",
                    "output": result.stdout
                })
                
            # Get IPv6 rules
            result = subprocess.run(
                ["ip6tables", "-L", "-n", "-v"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                self.rules.append({
                    "type": "iptables-ipv6",
                    "output": result.stdout
                })
        except Exception as e:
            self.issues.append({
                "issue": f"Failed to get iptables rules: {str(e)}",
                "recommendation": "Ensure iptables is properly installed and accessible",
                "severity": "medium"
            })
            
    def _get_firewalld_rules(self):
        """Get firewalld rules."""
        try:
            # Get zones
            result = subprocess.run(
                ["firewall-cmd", "--list-all-zones"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                self.rules.append({
                    "type": "firewalld-zones",
                    "output": result.stdout
                })
                
            # Get default zone
            result = subprocess.run(
                ["firewall-cmd", "--get-default-zone"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                default_zone = result.stdout.strip()
                
                # Get detailed info for the default zone
                result = subprocess.run(
                    ["firewall-cmd", "--zone=" + default_zone, "--list-all"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if result.returncode == 0:
                    self.rules.append({
                        "type": "firewalld-default-zone",
                        "zone": default_zone,
                        "output": result.stdout
                    })
        except Exception as e:
            self.issues.append({
                "issue": f"Failed to get firewalld rules: {str(e)}",
                "recommendation": "Ensure firewalld is properly installed and accessible",
                "severity": "medium"
            })
            
    def _get_ufw_rules(self):
        """Get ufw rules."""
        try:
            # Get rules
            result = subprocess.run(
                ["ufw", "status", "verbose"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                self.rules.append({
                    "type": "ufw-status",
                    "output": result.stdout
                })
        except Exception as e:
            self.issues.append({
                "issue": f"Failed to get ufw rules: {str(e)}",
                "recommendation": "Ensure ufw is properly installed and accessible",
                "severity": "medium"
            })
            
    def _analyze_firewall_rules(self):
        """Analyze firewall rules for security issues."""
        if not self.rules:
            return
            
        if self.active_firewall == "iptables":
            self._analyze_iptables_rules()
        elif self.active_firewall == "firewalld":
            self._analyze_firewalld_rules()
        elif self.active_firewall == "ufw":
            self._analyze_ufw_rules()
            
    def _analyze_iptables_rules(self):
        """Analyze iptables rules for security issues."""
        ipv4_rules = None
        ipv6_rules = None
        
        for rule_set in self.rules:
            if rule_set["type"] == "iptables-ipv4":
                ipv4_rules = rule_set["output"]
            elif rule_set["type"] == "iptables-ipv6":
                ipv6_rules = rule_set["output"]
                
        if not ipv4_rules:
            self.issues.append({
                "issue": "Could not analyze IPv4 iptables rules",
                "recommendation": "Ensure iptables is properly configured",
                "severity": "high"
            })
            return
            
        # Check default policies
        if "Chain INPUT (policy ACCEPT" in ipv4_rules:
            self.issues.append({
                "issue": "Default INPUT policy is set to ACCEPT",
                "recommendation": "Set default INPUT policy to DROP: 'iptables -P INPUT DROP'",
                "severity": "high"
            })
            
        if "Chain FORWARD (policy ACCEPT" in ipv4_rules:
            self.issues.append({
                "issue": "Default FORWARD policy is set to ACCEPT",
                "recommendation": "Set default FORWARD policy to DROP: 'iptables -P FORWARD DROP'",
                "severity": "high"
            })
            
        # Check for rules that might allow all traffic
        if re.search(r"ACCEPT\s+all\s+--\s+0\.0\.0\.0/0\s+0\.0\.0\.0/0", ipv4_rules):
            self.issues.append({
                "issue": "Rule allows all incoming traffic",
                "recommendation": "Remove overly permissive rules and use specific allow rules instead",
                "severity": "critical"
            })
            
        # Check for dangerous ports
        for port, service in self.DANGEROUS_PORTS.items():
            if re.search(rf"dpt:{port}[^-\d]", ipv4_rules) or re.search(rf":{port}\s", ipv4_rules):
                self.issues.append({
                    "issue": f"Potentially insecure service {service} (port {port}) is allowed",
                    "recommendation": f"Block or restrict access to {service} (port {port})",
                    "severity": "high"
                })
                
        # Check for stateful filtering
        if not re.search(r"RELATED,ESTABLISHED", ipv4_rules):
            self.issues.append({
                "issue": "No rule for ESTABLISHED,RELATED connections detected",
                "recommendation": "Add stateful filtering: 'iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT'",
                "severity": "medium"
            })
            
        # Check IPv6 rules if available
        if ipv6_rules:
            if "Chain INPUT (policy ACCEPT" in ipv6_rules:
                self.issues.append({
                    "issue": "Default IPv6 INPUT policy is set to ACCEPT",
                    "recommendation": "Set default IPv6 INPUT policy to DROP: 'ip6tables -P INPUT DROP'",
                    "severity": "high"
                })
                
    def _analyze_firewalld_rules(self):
        """Analyze firewalld rules for security issues."""
        default_zone_info = None
        
        for rule_set in self.rules:
            if rule_set["type"] == "firewalld-default-zone":
                default_zone_info = rule_set["output"]
                default_zone = rule_set.get("zone", "")
                break
                
        if not default_zone_info:
            self.issues.append({
                "issue": "Could not analyze firewalld default zone",
                "recommendation": "Ensure firewalld is properly configured",
                "severity": "high"
            })
            return
            
        # Check zone type
        if default_zone == "public":
            # This is OK for servers but might want to check specific configurations
            pass
        elif default_zone == "trusted":
            self.issues.append({
                "issue": "Default zone is set to 'trusted', which allows all traffic",
                "recommendation": "Use a more restrictive default zone like 'public' or 'drop'",
                "severity": "critical"
            })
            
        # Check for dangerous services
        for port, service in self.DANGEROUS_PORTS.items():
            service_lower = service.lower()
            port_str = str(port)
            
            if f"port={port}" in default_zone_info or f"port port=\"{port}\"" in default_zone_info or f"service name=\"{service_lower}\"" in default_zone_info:
                self.issues.append({
                    "issue": f"Potentially insecure service {service} (port {port}) is allowed",
                    "recommendation": f"Remove {service} service or port {port} from firewalld configuration",
                    "severity": "high"
                })
                
    def _analyze_ufw_rules(self):
        """Analyze ufw rules for security issues."""
        ufw_status = None
        
        for rule_set in self.rules:
            if rule_set["type"] == "ufw-status":
                ufw_status = rule_set["output"]
                break
                
        if not ufw_status:
            self.issues.append({
                "issue": "Could not analyze ufw rules",
                "recommendation": "Ensure ufw is properly configured",
                "severity": "high"
            })
            return
            
        # Check default policy
        if "Default: allow" in ufw_status:
            self.issues.append({
                "issue": "Default UFW policy is set to allow incoming traffic",
                "recommendation": "Set default policy to deny: 'ufw default deny incoming'",
                "severity": "high"
            })
            
        # Check for dangerous ports
        for port, service in self.DANGEROUS_PORTS.items():
            if re.search(rf"{port}(/| ).*ALLOW", ufw_status):
                self.issues.append({
                    "issue": f"Potentially insecure service {service} (port {port}) is allowed",
                    "recommendation": f"Block access to {service} (port {port}): 'ufw delete allow {port}/tcp'",
                    "severity": "high"
                })
                
    def remediate(self) -> bool:
        """
        Apply automatic remediation for firewall issues.
        
        Returns:
            bool: True if remediation was successful, False otherwise
        """
        # Check if running as root
        if os.geteuid() != 0:
            self.details = {"error": "Root privileges required for firewall remediation"}
            return False
            
        # Different remediation based on active firewall
        if self.active_firewall == "iptables":
            return self._remediate_iptables()
        elif self.active_firewall == "firewalld":
            return self._remediate_firewalld()
        elif self.active_firewall == "ufw":
            return self._remediate_ufw()
        else:
            # If no firewall is active, set up basic iptables rules
            return self._setup_basic_iptables()
    def _remediate_iptables(self) -> bool:
        """Apply remediation for iptables issues."""
        try:
            # Set default policies
            subprocess.run(["iptables", "-P", "INPUT", "DROP"], check=True)
            subprocess.run(["iptables", "-P", "FORWARD", "DROP"], check=True)
            subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True)
            
            # Flush existing rules
            subprocess.run(["iptables", "-F"], check=True)
            
            # Allow loopback traffic
            subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
            
            # Allow established and related connections
            subprocess.run([
                "iptables", "-A", "INPUT", "-m", "conntrack", 
                "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"
            ], check=True)
            
            # Allow SSH (can be customized)
            subprocess.run([
                "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"
            ], check=True)
            
            # IPv6 setup
            try:
                subprocess.run(["ip6tables", "-P", "INPUT", "DROP"], check=True)
                subprocess.run(["ip6tables", "-P", "FORWARD", "DROP"], check=True)
                subprocess.run(["ip6tables", "-P", "OUTPUT", "ACCEPT"], check=True)
                subprocess.run(["ip6tables", "-F"], check=True)
                subprocess.run(["ip6tables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
                subprocess.run([
                    "ip6tables", "-A", "INPUT", "-m", "conntrack", 
                    "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"
                ], check=True)
                subprocess.run([
                    "ip6tables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"
                ], check=True)
            except Exception as e:
                pass  # IPv6 might not be available, ignore errors
                
            # Save rules to persist across reboots
            try:
                if os.path.exists("/etc/debian_version"):
                    # Debian/Ubuntu
                    subprocess.run(["netfilter-persistent", "save"], check=True)
                elif os.path.exists("/etc/redhat-release"):
                    # RHEL/CentOS/Fedora
                    subprocess.run(["service", "iptables", "save"], check=True)
            except Exception as e:
                pass  # Saving might fail, but rules are still applied
                
            return True
        except Exception as e:
            self.details = {"error": f"Failed to apply iptables remediation: {str(e)}"}
            return False
            
    def _remediate_firewalld(self) -> bool:
        """Apply remediation for firewalld issues."""
        try:
            # Set default zone to public
            subprocess.run(["firewall-cmd", "--set-default-zone=public"], check=True)
            
            # Remove dangerous services
            for port, service in self.DANGEROUS_PORTS.items():
                service_lower = service.lower()
                try:
                    # Try to remove by service name
                    subprocess.run(["firewall-cmd", "--remove-service=" + service_lower, "--permanent"], check=False)
                    # Try to remove by port
                    subprocess.run([
                        "firewall-cmd", "--remove-port=" + str(port) + "/tcp", "--permanent"
                    ], check=False)
                except:
                    pass  # Ignore errors if service/port wasn't enabled
                    
            # Make sure essential services are available
            subprocess.run(["firewall-cmd", "--add-service=ssh", "--permanent"], check=True)
            
            # Reload to apply changes
            subprocess.run(["firewall-cmd", "--reload"], check=True)
            
            return True
        except Exception as e:
            self.details = {"error": f"Failed to apply firewalld remediation: {str(e)}"}
            return False
            
    def _remediate_ufw(self) -> bool:
        """Apply remediation for ufw issues."""
        try:
            # Reset to default
            subprocess.run(["ufw", "--force", "reset"], check=True)
            
            # Set default policies
            subprocess.run(["ufw", "default", "deny", "incoming"], check=True)
            subprocess.run(["ufw", "default", "allow", "outgoing"], check=True)
            
            # Allow SSH
            subprocess.run(["ufw", "allow", "ssh"], check=True)
            
            # Enable the firewall
            subprocess.run(["ufw", "--force", "enable"], check=True)
            
            return True
        except Exception as e:
            self.details = {"error": f"Failed to apply ufw remediation: {str(e)}"}
            return False
            
    def _setup_basic_iptables(self) -> bool:
        """Set up basic iptables rules if no firewall is active."""
        try:
            # Install iptables if not already installed
            if os.path.exists("/usr/bin/apt-get"):
                subprocess.run(["apt-get", "install", "-y", "iptables"], check=True)
            elif os.path.exists("/usr/bin/yum"):
                subprocess.run(["yum", "install", "-y", "iptables"], check=True)
                
            # Set up iptables with basic rules
            return self._remediate_iptables()
        except Exception as e:
            self.details = {"error": f"Failed to set up basic iptables: {str(e)}"}
            return False
            
    def get_remediation_script(self) -> str:
        """
        Get a remediation script for firewall issues.
        
        Returns:
            str: Bash script content
        """
        if self.active_firewall == "iptables":
            return self._get_iptables_script()
        elif self.active_firewall == "firewalld":
            return self._get_firewalld_script()
        elif self.active_firewall == "ufw":
            return self._get_ufw_script()
        else:
            return self._get_basic_firewall_script()
            
    def _get_iptables_script(self) -> str:
        """Get iptables remediation script."""
        script = [
            "#!/bin/bash",
            "# Iptables Firewall Security Remediation Script",
            "# This script applies security best practices to iptables configuration",
            "",
            "# Check if running as root",
            "if [ \"$(id -u)\" -ne 0 ]; then",
            "    echo \"This script must be run as root\" >&2",
            "    exit 1",
            "fi",
            "",
            "echo \"Applying secure iptables configuration...\"",
            "",
            "# Backup existing rules",
            "iptables-save > /tmp/iptables.bak",
            "ip6tables-save > /tmp/ip6tables.bak",
            "echo \"Backed up existing rules to /tmp/iptables.bak and /tmp/ip6tables.bak\"",
            "",
            "# Flush existing rules",
            "iptables -F",
            "iptables -X",
            "iptables -t nat -F",
            "iptables -t nat -X",
            "iptables -t mangle -F",
            "iptables -t mangle -X",
            "",
            "# Set default policies",
            "iptables -P INPUT DROP      # Block all incoming traffic by default",
            "iptables -P FORWARD DROP    # Block all forwarded traffic by default",
            "iptables -P OUTPUT ACCEPT   # Allow all outgoing traffic by default",
            "",
            "# Allow loopback traffic",
            "iptables -A INPUT -i lo -j ACCEPT",
            "",
            "# Allow established and related connections",
            "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "",
            "# Allow SSH (port 22)",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "",
            "# Uncomment to allow HTTP and HTTPS",
            "# iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
            "# iptables -A INPUT -p tcp --dport 443 -j ACCEPT",
            "",
            "# Block known dangerous ports",
            "iptables -A INPUT -p tcp --dport 21 -j DROP    # FTP",
            "iptables -A INPUT -p tcp --dport 23 -j DROP    # Telnet",
            "iptables -A INPUT -p tcp --dport 3389 -j DROP  # RDP",
            "iptables -A INPUT -p tcp --dport 5900 -j DROP  # VNC",
            "",
            "# Rate limiting for SSH to prevent brute force attacks",
            "iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set",
            "iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP",
            "",
            "# IPv6 configuration",
            "ip6tables -F",
            "ip6tables -X",
            "ip6tables -P INPUT DROP",
            "ip6tables -P FORWARD DROP",
            "ip6tables -P OUTPUT ACCEPT",
            "ip6tables -A INPUT -i lo -j ACCEPT",
            "ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
            "ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "",
            "echo \"Firewall rules applied successfully.\"",
            "",
            "# Save the rules to make them persistent",
            "if [ -f /etc/debian_version ]; then",
            "    # Debian/Ubuntu",
            "    if command -v netfilter-persistent >/dev/null 2>&1; then",
            "        netfilter-persistent save",
            "    else",
            "        echo \"Installing iptables-persistent package...\"",
            "        apt-get update && apt-get install -y iptables-persistent",
            "        netfilter-persistent save",
            "    fi",
            "elif [ -f /etc/redhat-release ]; then",
            "    # RHEL/CentOS/Fedora",
            "    service iptables save",
            "    service ip6tables save",
            "else",
            "    # Generic method",
            "    echo \"iptables-save > /etc/iptables.rules\" > /etc/network/if-pre-up.d/iptables",
            "    echo \"ip6tables-save > /etc/ip6tables.rules\" >> /etc/network/if-pre-up.d/iptables",
            "    echo \"iptables-restore < /etc/iptables.rules\" > /etc/network/if-post-down.d/iptables",
            "    echo \"ip6tables-restore < /etc/ip6tables.rules\" >> /etc/network/if-post-down.d/iptables",
            "    chmod +x /etc/network/if-pre-up.d/iptables /etc/network/if-post-down.d/iptables",
            "    iptables-save > /etc/iptables.rules",
            "    ip6tables-save > /etc/ip6tables.rules",
            "fi",
            "",
            "echo \"Iptables configuration hardening complete!\"",
            "exit 0"
        ]
        
        return "\n".join(script)
        
    def _get_firewalld_script(self) -> str:
        """Get firewalld remediation script."""
        script = [
            "#!/bin/bash",
            "# Firewalld Security Remediation Script",
            "# This script applies security best practices to firewalld configuration",
            "",
            "# Check if running as root",
            "if [ \"$(id -u)\" -ne 0 ]; then",
            "    echo \"This script must be run as root\" >&2",
            "    exit 1",
            "fi",
            "",
            "# Check if firewalld is installed",
            "if ! command -v firewall-cmd >/dev/null 2>&1; then",
            "    echo \"Firewalld is not installed\" >&2",
            "    echo \"Installing firewalld...\"",
            "    if command -v apt-get >/dev/null 2>&1; then",
            "        apt-get update && apt-get install -y firewalld",
            "    elif command -v yum >/dev/null 2>&1; then",
            "        yum install -y firewalld",
            "    else",
            "        echo \"Could not install firewalld automatically\" >&2",
            "        exit 1",
            "    fi",
            "fi",
            "",
            "# Start and enable firewalld",
            "systemctl start firewalld",
            "systemctl enable firewalld",
            "",
            "echo \"Applying secure firewalld configuration...\"",
            "",
            "# Set default zone to public",
            "firewall-cmd --set-default-zone=public",
            "",
            "# Remove dangerous services",
            "firewall-cmd --remove-service=ftp --permanent 2>/dev/null || true",
            "firewall-cmd --remove-service=telnet --permanent 2>/dev/null || true",
            "firewall-cmd --remove-service=vnc-server --permanent 2>/dev/null || true",
            "",
            "# Remove dangerous ports",
            "firewall-cmd --remove-port=21/tcp --permanent 2>/dev/null || true  # FTP",
            "firewall-cmd --remove-port=23/tcp --permanent 2>/dev/null || true  # Telnet",
            "firewall-cmd --remove-port=3389/tcp --permanent 2>/dev/null || true  # RDP",
            "firewall-cmd --remove-port=5900/tcp --permanent 2>/dev/null || true  # VNC",
            "",
            "# Ensure essential services are allowed",
            "firewall-cmd --add-service=ssh --permanent",
            "",
            "# Uncomment to allow HTTP and HTTPS",
            "# firewall-cmd --add-service=http --permanent",
            "# firewall-cmd --add-service=https --permanent",
            "",
            "# Reload to apply changes",
            "firewall-cmd --reload",
            "",
            "echo \"Firewalld configuration hardening complete!\"",
            "exit 0"
        ]
        
        return "\n".join(script)
        
    def _get_ufw_script(self) -> str:
        """Get ufw remediation script."""
        script = [
            "#!/bin/bash",
            "# UFW Security Remediation Script",
            "# This script applies security best practices to UFW configuration",
            "",
            "# Check if running as root",
            "if [ \"$(id -u)\" -ne 0 ]; then",
            "    echo \"This script must be run as root\" >&2",
            "    exit 1",
            "fi",
            "",
            "# Check if ufw is installed",
            "if ! command -v ufw >/dev/null 2>&1; then",
            "    echo \"UFW is not installed\" >&2",
            "    echo \"Installing ufw...\"",
            "    if command -v apt-get >/dev/null 2>&1; then",
            "        apt-get update && apt-get install -y ufw",
            "    elif command -v yum >/dev/null 2>&1; then",
            "        yum install -y ufw",
            "    else",
            "        echo \"Could not install ufw automatically\" >&2",
            "        exit 1",
            "    fi",
            "fi",
            "",
            "echo \"Applying secure UFW configuration...\"",
            "",
            "# Reset to default",
            "ufw --force reset",
            "",
            "# Set default policies",
            "ufw default deny incoming",
            "ufw default allow outgoing",
            "",
            "# Allow SSH",
            "ufw allow ssh",
            "",
            "# Uncomment to allow HTTP and HTTPS",
            "# ufw allow http",
            "# ufw allow https",
            "",
            "# Block known dangerous ports",
            "ufw deny 21/tcp  # FTP",
            "ufw deny 23/tcp  # Telnet",
            "ufw deny 3389/tcp  # RDP",
            "ufw deny 5900/tcp  # VNC",
            "",
            "# Enable the firewall",
            "ufw --force enable",
            "",
            "echo \"UFW configuration hardening complete!\"",
            "exit 0"
        ]
        
        return "\n".join(script)
        
    def _get_basic_firewall_script(self) -> str:
        """Get basic firewall setup script when no firewall is active."""
        # Default to iptables as it's the most widely available
        return self._get_iptables_script()