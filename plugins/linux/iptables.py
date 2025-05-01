"""
Iptables configuration security checks and remediations for Linux systems.
"""
import subprocess
from typing import Dict, Any, List
from core.plugin_loader import SecurityCheck
from integrations.nvd_client import NvdClient

class IptablesCheck(SecurityCheck):
    """
    Checks and remediates iptables firewall default policies and common rules.
    """
    CHECK_ID = "linux.iptables"
    TITLE = "Iptables Firewall Configuration"
    DESCRIPTION = "Ensure iptables has secure default policies and necessary rules"
    PLATFORM = "linux"
    SEVERITY = "medium"

    def __init__(self):
        super().__init__()
        self.details: Dict[str, Any] = {}
        self.cve_ids: List[str] = []
        self.nvd = NvdClient()

    def _run_cmd(self, cmd: List[str]) -> str:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        return result.stdout.strip()

    def check(self) -> bool:
        """
        Verify default INPUT, FORWARD, OUTPUT policies and presence of SSH allow rule.
        """
        all_ok = True
        # Check default policies
        for chain, desired in [("INPUT", "DROP"), ("FORWARD", "DROP"), ("OUTPUT", "ACCEPT")]:
            out = self._run_cmd(["iptables", "-L", chain, "-n"]).splitlines()[0]
            # Expected line format: Chain INPUT (policy ACCEPT)
            current = out.split("policy")[1].split(")")[0].strip() if "policy" in out else None
            passed = (current == desired)
            self.details[f"policy_{chain.lower()}"] = {"found": current, "expected": desired, "passed": passed}
            if not passed:
                all_ok = False

        # Check SSH rule exists (TCP port 22 ACCEPT)
        rules = self._run_cmd(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"])  # returns '' if exists
        ssh_ok = ("iptables: Bad rule" not in rules)
        self.details["ssh_rule"] = {"found": ssh_ok, "expected": True, "passed": ssh_ok}
        if not ssh_ok:
            all_ok = False

        # Fetch any CVEs relevant to iptables kernel module
        try:
            self.cve_ids = self.nvd.get_cves("iptables")
        except Exception:
            self.cve_ids = []

        self.passed = all_ok
        return all_ok

    def remediate(self) -> bool:
        """
        Apply secure default policies and add SSH accept rule.
        """
        try:
            # Set default policies
            subprocess.run(["iptables", "-P", "INPUT", "DROP"], check=True)
            subprocess.run(["iptables", "-P", "FORWARD", "DROP"], check=True)
            subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True)

            # Insert SSH rule if missing
            subprocess.run(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"], check=False)
            subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"], check=True)

            return True
        except subprocess.CalledProcessError as e:
            self.details = {"remediation_error": str(e)}
            return False

    def get_remediation_script(self) -> str:
        """
        Returns a bash script for manual iptables remediation.
        """
        return """
#!/usr/bin/env bash
# Reset default policies
iptables -P INPUT DROP  # Drop all incoming by default
iptables -P FORWARD DROP  # Drop all forwarded by default
iptables -P OUTPUT ACCEPT  # Allow all outgoing by default

# Allow SSH
iptables -C INPUT -p tcp --dport 22 -j ACCEPT || iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # Insert SSH rule if missing

# Save rules
iptables-save > /etc/iptables/rules.v4  # Persist on Debian/Ubuntu systems
"""
