#!/usr/bin/env python3
# Core scanner implementation

import os
import time
import json
import logging
import threading
from queue import Queue
from typing import List, Dict, Any, Callable, Optional
from datetime import datetime

from core.plugin_loader import PluginLoader

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scanner")

class ScanResult:
    """Container for scan results."""
    
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.timestamp = datetime.now()
        self.platform_info = {}
        self.results = {}
        self.check_count = 0
        self.passed_count = 0
        self.failed_count = 0
        self.in_progress = True
        self.duration = 0
        
    def add_result(self, check_id: str, result: dict):
        """Add a check result to the scan results."""
        self.results[check_id] = result
        self.check_count += 1
        if result.get("passed", False):
            self.passed_count += 1
        else:
            self.failed_count += 1
    
    def finalize(self, duration: float):
        """Mark the scan as complete and calculate statistics."""
        self.in_progress = False
        self.duration = duration
        
    def to_dict(self) -> dict:
        """Convert scan result to a dictionary."""
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp.isoformat(),
            "platform_info": self.platform_info,
            "results": self.results,
            "check_count": self.check_count,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "in_progress": self.in_progress,
            "duration": self.duration
        }
    
    def save_to_file(self, filename: str):
        """Save scan results to a JSON file."""
        with open(filename, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
            
    @staticmethod
    def load_from_file(filename: str) -> 'ScanResult':
        """Load scan results from a JSON file."""
        with open(filename, 'r') as f:
            data = json.load(f)
        
        result = ScanResult(data["scan_id"])
        result.timestamp = datetime.fromisoformat(data["timestamp"])
        result.platform_info = data["platform_info"]
        result.results = data["results"]
        result.check_count = data["check_count"]
        result.passed_count = data["passed_count"]
        result.failed_count = data["failed_count"]
        result.in_progress = data["in_progress"]
        result.duration = data["duration"]
        
        return result


class Scanner:
    """Main security scanner implementation."""
    
    def __init__(self, plugin_dirs: List[str], report_dir: str):
        """
        Initialize the scanner.
        
        Args:
            plugin_dirs: List of directories containing security check plugins
            report_dir: Directory to store scan reports
        """
        self.plugin_loader = PluginLoader(plugin_dirs)
        self.report_dir = report_dir
        self.current_scan = None
        self._worker_threads = []
        self._task_queue = Queue()
        self._progress_callback = None
        self._complete_callback = None
        
        # Create reports directory if it doesn't exist
        os.makedirs(report_dir, exist_ok=True)
        
    def get_available_checks(self) -> dict:
        """
        Get all available security checks.
        
        Returns:
            dict: Dictionary mapping check IDs to check information
        """
        checks = {}
        for check_id, check_class in self.plugin_loader.get_available_checks().items():
            checks[check_id] = {
                "id": check_id,
                "title": check_class.TITLE,
                "description": check_class.DESCRIPTION,
                "platform": check_class.PLATFORM,
                "severity": check_class.SEVERITY
            }
        return checks
    
    def start_scan(self, 
                  check_ids: List[str], 
                  platform_info: dict,
                  num_threads: int = 4,
                  progress_callback: Optional[Callable[[str, dict], None]] = None,
                  complete_callback: Optional[Callable[[ScanResult], None]] = None) -> str:
        """
        Start a new security scan.
        
        Args:
            check_ids: List of check IDs to run
            platform_info: Information about the current platform
            num_threads: Number of worker threads to use
            progress_callback: Function to call with progress updates
            complete_callback: Function to call when the scan completes
            
        Returns:
            str: The scan ID
        """
        # Generate a unique scan ID
        scan_id = f"scan_{int(time.time())}"
        
        # Create a new scan result
        self.current_scan = ScanResult(scan_id)
        self.current_scan.platform_info = platform_info
        
        # Store callbacks
        self._progress_callback = progress_callback
        self._complete_callback = complete_callback
        
        # Start worker threads
        self._start_workers(num_threads)
        
        # Queue all checks
        for check_id in check_ids:
            self._task_queue.put(check_id)
            
        # Add sentinel values to signal workers to stop
        for _ in range(num_threads):
            self._task_queue.put(None)
            
        # Start a monitoring thread
        monitor_thread = threading.Thread(target=self._monitor_scan, args=(scan_id,))
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return scan_id
    
    def _start_workers(self, num_threads: int):
        """Start worker threads."""
        self._worker_threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=self._worker_thread)
            thread.daemon = True
            thread.start()
            self._worker_threads.append(thread)
    
    def _worker_thread(self):
        """Worker thread function."""
        while True:
            check_id = self._task_queue.get()
            if check_id is None:  # Sentinel value
                break
                
            try:
                # Run the check and store the result
                result = self.plugin_loader.run_check(check_id)
                
                # Update the scan result
                self.current_scan.add_result(check_id, result)
                
                # Call progress callback if provided
                if self._progress_callback:
                    self._progress_callback(check_id, result)
            except Exception as e:
                logger.error(f"Error running check {check_id}: {e}")
                # Log error in scan results
                self.current_scan.add_result(check_id, {
                    "check_id": check_id,
                    "error": str(e),
                    "passed": False,
                    "details": {"error": str(e)},
                    "cve_ids": []
                })
            finally:
                self._task_queue.task_done()
    
    def _monitor_scan(self, scan_id: str):
        """Monitor the scan and finalize when complete."""
        start_time = time.time()
        
        # Wait for all tasks to complete
        while not self._task_queue.empty():
            time.sleep(0.1)
            
        # Wait for worker threads to complete
        for thread in self._worker_threads:
            thread.join()
            
        # Calculate duration and finalize scan
        duration = time.time() - start_time
        self.current_scan.finalize(duration)
        
        # Save the scan result
        filename = os.path.join(self.report_dir, f"{scan_id}.json")
        self.current_scan.save_to_file(filename)
        
        # Call complete callback if provided
        if self._complete_callback:
            self._complete_callback(self.current_scan)
            
        logger.info(f"Scan {scan_id} completed in {duration:.2f} seconds")
        
    def get_previous_scans(self) -> List[str]:
        """
        Get a list of previous scan IDs.
        
        Returns:
            List[str]: List of scan IDs
        """
        scans = []
        if os.path.exists(self.report_dir):
            for file in os.listdir(self.report_dir):
                if file.endswith('.json') and file.startswith('scan_'):
                    scans.append(file[:-5])  # Remove .json extension
        return sorted(scans, reverse=True)
    
    def load_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """
        Load a previous scan result.
        
        Args:
            scan_id: The scan ID
            
        Returns:
            Optional[ScanResult]: The scan result if found, None otherwise
        """
        filename = os.path.join(self.report_dir, f"{scan_id}.json")
        if os.path.exists(filename):
            return ScanResult.load_from_file(filename)
        return None
    
    def compare_scans(self, old_scan_id: str, new_scan_id: str) -> Dict[str, Any]:
        """
        Compare two scan results and identify changes.
        
        Args:
            old_scan_id: The older scan ID
            new_scan_id: The newer scan ID
            
        Returns:
            Dict[str, Any]: Comparison results
        """
        old_scan = self.load_scan_result(old_scan_id)
        new_scan = self.load_scan_result(new_scan_id)
        
        if not old_scan or not new_scan:
            return {"error": "One or both scans not found"}
            
        comparison = {
            "old_scan_id": old_scan_id,
            "new_scan_id": new_scan_id,
            "improved": [],  # Checks that were failing and now pass
            "regressed": [], # Checks that were passing and now fail
            "fixed": [],     # New checks that pass
            "new_issues": [] # New checks that fail
        }
        
        # Find checks in both scans
        common_checks = set(old_scan.results.keys()) & set(new_scan.results.keys())
        
        # Find checks only in the new scan
        new_checks = set(new_scan.results.keys()) - set(old_scan.results.keys())
        
        # Check for improvements and regressions
        for check_id in common_checks:
            old_passed = old_scan.results[check_id].get("passed", False)
            new_passed = new_scan.results[check_id].get("passed", False)
            
            if not old_passed and new_passed:
                comparison["improved"].append(check_id)
            elif old_passed and not new_passed:
                comparison["regressed"].append(check_id)
                
        # Check for new fixed issues and new issues
        for check_id in new_checks:
            passed = new_scan.results[check_id].get("passed", False)
            if passed:
                comparison["fixed"].append(check_id)
            else:
                comparison["new_issues"].append(check_id)
                
        return comparison
    
    def remediate(self, check_id: str) -> dict:
        """
        Apply remediation for a specific check.
        
        Args:
            check_id: The check ID
            
        Returns:
            dict: The remediation result
        """
        check_instance = self.plugin_loader.create_check_instance(check_id)
        if not check_instance:
            return {"success": False, "message": f"Check {check_id} not found"}
            
        try:
            success = check_instance.remediate()
            message = "Remediation successful" if success else "Remediation failed"
            return {"success": success, "message": message}
        except Exception as e:
            logger.error(f"Error applying remediation for {check_id}: {e}")
            return {"success": False, "message": str(e)}
    
    def get_remediation_script(self, check_id: str) -> str:
        """
        Get the remediation script for a specific check.
        
        Args:
            check_id: The check ID
            
        Returns:
            str: The remediation script
        """
        check_instance = self.plugin_loader.create_check_instance(check_id)
        if not check_instance:
            return f"# Error: Check {check_id} not found"
            
        try:
            return check_instance.get_remediation_script()
        except Exception as e:
            logger.error(f"Error getting remediation script for {check_id}: {e}")
            return f"# Error: {str(e)}"
