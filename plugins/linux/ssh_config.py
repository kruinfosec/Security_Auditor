"""
SSH configuration security checks and remediations for Linux systems.
"""
import os
import re
import subprocess
from typing import Dict, List, Any
from core.plugin_loader import SecurityCheck
from integrations.nvd_client import NvdClient

# Plugin for SSH config security auditing
class SSHConfigCheck(SecurityCheck):
    """
    SSH Configuration checker for Linux systems.
    Checks various SSH configuration settings for security best practices.
    """

    CHECK_ID = "linux.ssh_config"
    TITLE = "SSH Configuration Security"
    DESCRIPTION = "Checks for secure SSH configuration settings"
    PLATFORM = "linux"
    SEVERITY = "high"

    CONFIG_PATH = "/etc/ssh/sshd_config"
    BACKUP_PATH = "/etc/ssh/sshd_config.bak"
    EXPECTED_SETTINGS = {
        "PermitRootLogin": "no",
        "PasswordAuthentication": "no",
        "PubkeyAuthentication": "yes",
        "PermitEmptyPasswords": "no",
        "MaxAuthTries": "4",
        "PermitUserEnvironment": "no",
        "AllowTcpForwarding": "no",
        "Protocol": "2"
    }

    def __init__(self):
        super().__init__()
        self.nvd = NvdClient()
        self.details: Dict[str, Any] = {}
        self.cve_ids: List[str] = []

    def check(self) -> bool:
        """
        Perform all SSH configuration checks, populate details, and fetch related CVEs.
        """
        if not os.path.exists(self.CONFIG_PATH):
            self.details = {"error": f"{self.CONFIG_PATH} not found"}
            self.passed = False
            return False

        with open(self.CONFIG_PATH, 'r') as f:
            content = f.read()

        self.details = {}
        all_ok = True
        # Check each expected setting
        for key, expected in self.EXPECTED_SETTINGS.items():
            pattern = rf"^\s*{key}\s+(\S+)"
            match = re.search(pattern, content, re.MULTILINE)
            if match:
                actual = match.group(1)
                ok = (actual.lower() == expected.lower())
                self.details[key] = {"found": actual, "expected": expected, "passed": ok}
                if not ok:
                    all_ok = False
            else:
                # missing directive is a fail or warning
                self.details[key] = {"found": None, "expected": expected, "passed": False}
                all_ok = False

        # Fetch CVEs for OpenSSH
        try:
            self.cve_ids = self.nvd.get_cves("OpenSSH")
        except Exception:
            self.cve_ids = []

        self.passed = all_ok
        return all_ok

    def remediate(self) -> bool:
        """
        Backup, apply secure settings, and restart sshd service.
        """
        try:
            # Backup the original config
            subprocess.run(["cp", self.CONFIG_PATH, self.BACKUP_PATH], check=True)

            # Read existing lines
            with open(self.CONFIG_PATH, 'r') as f:
                lines = f.readlines()

            new_lines: List[str] = []
            for line in lines:
                updated = False
                for key, expected in self.EXPECTED_SETTINGS.items():
                    if re.match(rf"^\s*{key}\b", line):
                        new_lines.append(f"{key} {expected}\n")
                        updated = True
                        break
                if not updated:
                    new_lines.append(line)

            # Append missing directives
            for key, expected in self.EXPECTED_SETTINGS.items():
                if not any(re.match(rf"^\s*{key}\b", l) for l in new_lines):
                    new_lines.append(f"{key} {expected}\n")

            # Write updated config
            with open(self.CONFIG_PATH, 'w') as f:
                f.writelines(new_lines)

            # Restart SSH service
            subprocess.run(["systemctl", "restart", "sshd"], check=True)
            return True
        except Exception as e:
            self.details = {"remediation_error": str(e)}
            return False

    def get_remediation_script(self) -> str:
        """
        Returns a bash script for manual remediation of SSH settings.
        """
        lines: List[str] = []
        # Shebang and backup
        lines.append("#!/usr/bin/env bash")
        lines.append("")
        lines.append("# Backup current sshd_config")
        lines.append(f"cp {self.CONFIG_PATH} {self.BACKUP_PATH}")
        lines.append("")

        # Iterate through each setting
        for key, expected in self.EXPECTED_SETTINGS.items():
            lines.append(f"# Ensure {key} is set to {expected}")
            lines.append(f"if grep -qE '^\\s*{key}\\s+' {self.CONFIG_PATH}; then")
            lines.append(f"    sed -i 's|^\\s*{key}\\s.*|{key} {expected}|' {self.CONFIG_PATH}")
            lines.append("else")
            lines.append(f"    echo '{key} {expected}' >> {self.CONFIG_PATH}")
            lines.append("fi")
            lines.append("")

        # Final restart
        lines.append("# Restart SSH service")
        lines.append("echo 'Restarting sshd...'" )
        lines.append("systemctl restart sshd")

        return "\n".join(lines)
