#!/usr/bin/env python3
# System detection and utility functions

import os
import platform
import subprocess
import sys

def get_platform_info():
    """
    Detect the current platform and return detailed information.
    
    Returns:
        dict: Platform information including OS, version, and architecture
    """
    system = platform.system().lower()
    info = {
        'os': system,
        'version': platform.version(),
        'architecture': platform.architecture()[0],
        'machine': platform.machine(),
        'processor': platform.processor(),
        'is_admin': is_admin()
    }
    
    # Add platform-specific details
    if system == 'windows':
        info['windows_edition'] = platform.win32_edition() if hasattr(platform, 'win32_edition') else "Unknown"
    elif system == 'linux':
        info['distro'] = get_linux_distro()
    elif system == 'darwin':  # macOS
        info['os'] = 'macos'
        info['macos_version'] = platform.mac_ver()[0]
        
    return info

def get_linux_distro():
    """Get Linux distribution details."""
    try:
        # Try to get distribution info from os-release file
        if os.path.exists('/etc/os-release'):
            with open('/etc/os-release', 'r') as f:
                lines = f.readlines()
                distro_info = {}
                for line in lines:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        distro_info[key] = value.strip('"')
                return distro_info.get('PRETTY_NAME', 'Unknown Linux')
        # Fallback to platform module
        return ' '.join(platform.linux_distribution())
    except:
        return "Unknown Linux"

def is_admin():
    """
    Check if the current process has administrator/root privileges.
    
    Returns:
        bool: True if running with elevated privileges, False otherwise
    """
    if platform.system().lower() == 'windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:  # Unix-based systems (Linux, macOS)
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False

def execute_command(command, shell=False, timeout=30):
    """
    Safely execute a system command.
    
    Args:
        command (list or str): Command to execute
        shell (bool): Whether to use shell execution
        timeout (int): Command timeout in seconds
        
    Returns:
        tuple: (stdout, stderr, return_code)
    """
    try:
        # For security, prefer list form of commands when shell=False
        if isinstance(command, str) and not shell:
            command = command.split()
            
        # Execute the command with appropriate safety measures
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=shell,
            text=True,
            encoding='utf-8'
        )
        stdout, stderr = process.communicate(timeout=timeout)
        return stdout, stderr, process.returncode
    except subprocess.TimeoutExpired:
        return '', 'Command timed out', -1
    except Exception as e:
        return '', f'Error executing command: {str(e)}', -1
