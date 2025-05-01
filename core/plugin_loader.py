#!/usr/bin/env python3
# Plugin loading and management system

import os
import sys
import importlib
import inspect
import logging
from typing import Dict, List, Any, Type, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("plugin_loader")

class SecurityCheck:
    """Base class for all security check plugins."""
    
    # Required class attributes for all plugins
    CHECK_ID = "base.check"  # Unique identifier
    TITLE = "Base Security Check"  # User-friendly title
    DESCRIPTION = "Base class for security checks"  # Detailed description
    PLATFORM = "any"  # "windows", "linux", "macos", or "any"
    SEVERITY = "medium"  # low, medium, high, critical
    
    def __init__(self):
        """Initialize security check."""
        self.result = None
        self.details = {}
        self.cve_ids = []
        self.passed = None
        
    def check(self) -> bool:
        """
        Perform the security check.
        
        Returns:
            bool: True if the check passed, False otherwise
        """
        raise NotImplementedError("Subclasses must implement this method")
    
    def remediate(self) -> bool:
        """
        Apply automatic remediation.
        
        Returns:
            bool: True if remediation was successful, False otherwise
        """
        raise NotImplementedError("Subclasses must implement this method")
    
    def get_remediation_script(self) -> str:
        """
        Get the remediation script (bash/PowerShell).
        
        Returns:
            str: Script content
        """
        raise NotImplementedError("Subclasses must implement this method")
    
    def get_result(self) -> dict:
        """
        Get the check result and details.
        
        Returns:
            dict: Result information including status and details
        """
        if self.result is None:
            raise ValueError("Check has not been executed yet")
        
        return {
            "check_id": self.CHECK_ID,
            "title": self.TITLE,
            "description": self.DESCRIPTION,
            "platform": self.PLATFORM,
            "severity": self.SEVERITY,
            "passed": self.passed,
            "details": self.details,
            "cve_ids": self.cve_ids
        }


class PluginLoader:
    """Loads and manages security check plugins."""
    
    def __init__(self, plugin_dirs: List[str]):
        """
        Initialize the plugin loader.
        
        Args:
            plugin_dirs: List of directories to search for plugins
        """
        self.plugin_dirs = plugin_dirs
        self.plugins: Dict[str, Type[SecurityCheck]] = {}
        self.available_checks: Dict[str, Type[SecurityCheck]] = {}
        self._load_plugins()
    
    def _load_plugins(self):
        """Discover and load all plugins from the specified directories."""
        for plugin_dir in self.plugin_dirs:
            if not os.path.exists(plugin_dir):
                logger.warning(f"Plugin directory not found: {plugin_dir}")
                continue
                
            # Add the plugin directory to the Python path
            if plugin_dir not in sys.path:
                sys.path.insert(0, plugin_dir)
            
            # Walk through the directory and find Python modules
            for root, dirs, files in os.walk(plugin_dir):
                for file in files:
                    if file.endswith('.py') and not file.startswith('__'):
                        # Convert file path to module path
                        rel_path = os.path.relpath(root, plugin_dir)
                        module_path = os.path.join(rel_path, file[:-3]).replace(os.sep, '.')
                        
                        if module_path.startswith('.'):
                            module_path = module_path[1:]
                            
                        try:
                            # Import the module
                            module = importlib.import_module(module_path)
                            
                            # Find all SecurityCheck subclasses in the module
                            for name, obj in inspect.getmembers(module):
                                if (inspect.isclass(obj) and 
                                    issubclass(obj, SecurityCheck) and 
                                    obj != SecurityCheck):
                                    # Register the check
                                    self.plugins[obj.CHECK_ID] = obj
                                    logger.info(f"Loaded plugin: {obj.CHECK_ID} - {obj.TITLE}")
                        except (ImportError, AttributeError) as e:
                            logger.error(f"Failed to load plugin module {module_path}: {e}")
        
        # Filter available checks for the current platform
        self._filter_checks_by_platform()
                            
    def _filter_checks_by_platform(self):
        """Filter the loaded plugins based on the current platform."""
        current_platform = sys.platform
        platform_map = {
            'win32': 'windows',
            'linux': 'linux',
            'darwin': 'macos'
        }
        current_platform = platform_map.get(current_platform, current_platform)
        
        for check_id, check_class in self.plugins.items():
            if check_class.PLATFORM.lower() in ['any', current_platform]:
                self.available_checks[check_id] = check_class
    
    def get_available_checks(self) -> Dict[str, Type[SecurityCheck]]:
        """
        Get all available security checks for the current platform.
        
        Returns:
            Dict[str, Type[SecurityCheck]]: Dictionary of check IDs to check classes
        """
        return self.available_checks
    
    def get_check_by_id(self, check_id: str) -> Optional[Type[SecurityCheck]]:
        """
        Get a security check by its ID.
        
        Args:
            check_id: The unique ID of the check
            
        Returns:
            Optional[Type[SecurityCheck]]: The check class if found, None otherwise
        """
        return self.available_checks.get(check_id)
    
    def create_check_instance(self, check_id: str) -> Optional[SecurityCheck]:
        """
        Create an instance of a security check.
        
        Args:
            check_id: The unique ID of the check
            
        Returns:
            Optional[SecurityCheck]: A new check instance if found, None otherwise
        """
        check_class = self.get_check_by_id(check_id)
        if check_class:
            return check_class()
        return None
        
    def run_check(self, check_id: str) -> dict:
        """
        Run a specific security check and return the result.
        
        Args:
            check_id: The unique ID of the check
            
        Returns:
            dict: The check result
        """
        check = self.create_check_instance(check_id)
        if not check:
            return {"error": f"Check {check_id} not found"}
        
        try:
            check.passed = check.check()
            return check.get_result()
        except Exception as e:
            logger.error(f"Error running check {check_id}: {e}")
            return {
                "check_id": check_id,
                "error": str(e),
                "passed": False,
                "details": {"error": str(e)},
                "cve_ids": []
            }
