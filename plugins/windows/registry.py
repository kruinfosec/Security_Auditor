"""
Windows registry security checks for key security-related settings.
"""
import winreg
from typing import Dict, List, Any

PLUGIN_ID = "windows.registry"
PLUGIN_NAME = "Windows Registry Security"
PLUGIN_DESCRIPTION = "Checks Windows registry for key security settings."


class WindowsRegistryCheck:
    def __init__(self):
        self.hive = winreg.HKEY_LOCAL_MACHINE

    def _read_value(self, path: str, name: str) -> Any:
        """Reads a value from the registry"""
        try:
            with winreg.OpenKey(self.hive, path, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return value
        except FileNotFoundError:
            return None
        except Exception as e:
            return f"Error: {e}"

    def run_checks(self) -> List[Dict[str, Any]]:
        """Runs registry-based security checks"""
        checks = []

        checks.append(self._check_uac_enabled())
        checks.append(self._check_rdp_enabled())
        checks.append(self._check_guest_account_status())

        return checks

    def _check_uac_enabled(self) -> Dict[str, Any]:
        """Check if UAC is enabled"""
        path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        value = self._read_value(path, "EnableLUA")

        if value == 1:
            status = "pass"
        elif value == 0:
            status = "fail"
        else:
            status = "warning"

        return {
            "id": f"{PLUGIN_ID}.uac",
            "title": "User Account Control (UAC)",
            "description": "Checks whether UAC is enabled",
            "status": status,
            "details": {
                "current_value": value,
                "recommended_value": 1
            },
            "remediation": """
# To enable UAC via registry:
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f
""",
            "cve_ids": ["CVE-2010-0023"]
        }

    def _check_rdp_enabled(self) -> Dict[str, Any]:
        """Check if Remote Desktop is enabled"""
        path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
        value = self._read_value(path, "fDenyTSConnections")

        if value == 0:
            status = "fail"
        elif value == 1:
            status = "pass"
        else:
            status = "warning"

        return {
            "id": f"{PLUGIN_ID}.rdp",
            "title": "Remote Desktop Access",
            "description": "Checks whether Remote Desktop is disabled",
            "status": status,
            "details": {
                "current_value": value,
                "recommended_value": 1
            },
            "remediation": """
# To disable Remote Desktop via registry:
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
""",
            "cve_ids": ["CVE-2020-0609"]
        }

    def _check_guest_account_status(self) -> Dict[str, Any]:
        """Check if Guest account is disabled"""
        path = r"SAM\SAM\Domains\Account\Users\Names\Guest"
        value = self._read_value(path, "")

        if value is None:
            status = "pass"
        else:
            status = "fail"

        return {
            "id": f"{PLUGIN_ID}.guest_account",
            "title": "Guest Account Status",
            "description": "Checks whether the Guest account is disabled",
            "status": status,
            "details": {
                "present": value is not None
            },
            "remediation": """
# Disable Guest account:
net user Guest /active:no
""",
            "cve_ids": ["CVE-2003-0001"]
        }
