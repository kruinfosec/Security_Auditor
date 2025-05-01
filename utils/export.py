#!/usr/bin/env python3
# Report generation utilities for Security Auditor Tool

import os
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("export")

def export_to_format(scan_result: dict, format_type: str, output_file: Optional[str] = None) -> str:
    """
    Export scan results to the specified format.
    
    Args:
        scan_result: Dictionary containing scan results
        format_type: Type of export ('html', 'text', 'json')
        output_file: Optional filename for the export
        
    Returns:
        str: Path to the exported file
    """
    generator = ReportGenerator()
    
    if format_type.lower() == 'html':
        return generator.generate_html_report(scan_result, output_file)
    elif format_type.lower() == 'text':
        return generator.generate_text_report(scan_result, output_file)
    elif format_type.lower() == 'json':
        return generator.generate_json_report(scan_result, output_file)
    else:
        raise ValueError(f"Unsupported export format: {format_type}")


class ReportGenerator:
    """Generate reports from scan results in various formats."""
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize the report generator.
        
        Args:
            output_dir: Directory to store generated reports
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def generate_html_report(self, scan_result: dict, filename: Optional[str] = None) -> str:
        """
        Generate an HTML report from scan results.
        
        Args:
            scan_result: Dictionary containing scan results
            filename: Optional filename to save the report, if None a default name is generated
            
        Returns:
            str: Path to the generated HTML report
        """
        # Generate default filename if not provided
        if filename is None:
            timestamp = datetime.fromtimestamp(int(scan_result['scan_id'].split('_')[1]))
            filename = f"security_report_{timestamp.strftime('%Y%m%d_%H%M%S')}.html"
        
        # Ensure the filename has .html extension
        if not filename.endswith('.html'):
            filename += '.html'
            
        filepath = os.path.join(self.output_dir, filename)
        
        # Generate HTML content
        html_content = self._create_html_content(scan_result)
        
        # Write HTML to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        logger.info(f"HTML report generated: {filepath}")
        return filepath
    
    def generate_text_report(self, scan_result: dict, filename: Optional[str] = None) -> str:
        """
        Generate a plain text report from scan results.
        
        Args:
            scan_result: Dictionary containing scan results
            filename: Optional filename to save the report, if None a default name is generated
            
        Returns:
            str: Path to the generated text report
        """
        # Generate default filename if not provided
        if filename is None:
            timestamp = datetime.fromtimestamp(int(scan_result['scan_id'].split('_')[1]))
            filename = f"security_report_{timestamp.strftime('%Y%m%d_%H%M%S')}.txt"
        
        # Ensure the filename has .txt extension
        if not filename.endswith('.txt'):
            filename += '.txt'
            
        filepath = os.path.join(self.output_dir, filename)
        
        # Generate text content
        text_content = self._create_text_content(scan_result)
        
        # Write text to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(text_content)
            
        logger.info(f"Text report generated: {filepath}")
        return filepath
    
    def generate_json_report(self, scan_result: dict, filename: Optional[str] = None) -> str:
        """
        Generate a JSON report from scan results.
        
        Args:
            scan_result: Dictionary containing scan results
            filename: Optional filename to save the report, if None a default name is generated
            
        Returns:
            str: Path to the generated JSON report
        """
        # Generate default filename if not provided
        if filename is None:
            timestamp = datetime.fromtimestamp(int(scan_result['scan_id'].split('_')[1]))
            filename = f"security_report_{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
        
        # Ensure the filename has .json extension
        if not filename.endswith('.json'):
            filename += '.json'
            
        filepath = os.path.join(self.output_dir, filename)
        
        # Write JSON to file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(scan_result, f, indent=2)
            
        logger.info(f"JSON report generated: {filepath}")
        return filepath
    
    def generate_comparison_report(self, old_scan: dict, new_scan: dict, filename: Optional[str] = None) -> str:
        """
        Generate an HTML comparison report between two scans.
        
        Args:
            old_scan: Dictionary containing the older scan results
            new_scan: Dictionary containing the newer scan results
            filename: Optional filename to save the report, if None a default name is generated
            
        Returns:
            str: Path to the generated comparison report
        """
        # Generate default filename if not provided
        if filename is None:
            old_timestamp = datetime.fromtimestamp(int(old_scan['scan_id'].split('_')[1]))
            new_timestamp = datetime.fromtimestamp(int(new_scan['scan_id'].split('_')[1]))
            filename = f"comparison_{old_timestamp.strftime('%Y%m%d')}_{new_timestamp.strftime('%Y%m%d')}.html"
        
        # Ensure the filename has .html extension
        if not filename.endswith('.html'):
            filename += '.html'
            
        filepath = os.path.join(self.output_dir, filename)
        
        # Generate comparison content
        comparison_data = self._generate_comparison_data(old_scan, new_scan)
        html_content = self._create_comparison_html(old_scan, new_scan, comparison_data)
        
        # Write HTML to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        logger.info(f"Comparison report generated: {filepath}")
        return filepath
    
    def _generate_comparison_data(self, old_scan: dict, new_scan: dict) -> dict:
        """Generate comparison data between two scans."""
        comparison = {
            "improved": [],  # Checks that were failing and now pass
            "regressed": [], # Checks that were passing and now fail
            "fixed": [],     # New checks that pass
            "new_issues": [] # New checks that fail
        }
        
        # Find checks in both scans
        common_checks = set(old_scan['results'].keys()) & set(new_scan['results'].keys())
        
        # Find checks only in the new scan
        new_checks = set(new_scan['results'].keys()) - set(old_scan['results'].keys())
        
        # Check for improvements and regressions
        for check_id in common_checks:
            old_passed = old_scan['results'][check_id].get("passed", False)
            new_passed = new_scan['results'][check_id].get("passed", False)
            
            if not old_passed and new_passed:
                comparison["improved"].append({
                    "check_id": check_id,
                    "title": new_scan['results'][check_id].get("title", check_id),
                    "severity": new_scan['results'][check_id].get("severity", "medium")
                })
            elif old_passed and not new_passed:
                comparison["regressed"].append({
                    "check_id": check_id,
                    "title": new_scan['results'][check_id].get("title", check_id),
                    "severity": new_scan['results'][check_id].get("severity", "medium")
                })
                
        # Check for new fixed issues and new issues
        for check_id in new_checks:
            passed = new_scan['results'][check_id].get("passed", False)
            if passed:
                comparison["fixed"].append({
                    "check_id": check_id,
                    "title": new_scan['results'][check_id].get("title", check_id),
                    "severity": new_scan['results'][check_id].get("severity", "medium")
                })
            else:
                comparison["new_issues"].append({
                    "check_id": check_id,
                    "title": new_scan['results'][check_id].get("title", check_id),
                    "severity": new_scan['results'][check_id].get("severity", "medium")
                })
                
        return comparison
    
    def _create_html_content(self, scan_result: dict) -> str:
        """Create HTML report content from scan results."""
        # Extract scan info
        scan_id = scan_result['scan_id']
        timestamp = datetime.fromisoformat(scan_result['timestamp'])
        platform_info = scan_result['platform_info']
        results = scan_result['results']
        
        # Calculate statistics
        total_checks = scan_result['check_count']
        passed_checks = scan_result['passed_count']
        failed_checks = scan_result['failed_count']
        pass_rate = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        # Count issues by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for check_id, result in results.items():
            if not result.get("passed", False):
                severity = result.get("severity", "medium").lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        # Begin HTML content with CSS styling
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {timestamp.strftime('%Y-%m-%d %H:%M:%S')}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        h1, h2, h3, h4 {{
            color: #2c3e50;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background-color: #34495e;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
        }}
        .summary {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
        }}
        .summary-box {{
            flex: 1;
            padding: 15px;
            margin: 0 10px;
            background-color: #f8f9fa;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .summary-box h3 {{
            margin-top: 0;
        }}
        .progress-bar {{
            height: 20px;
            background-color: #e74c3c;
            border-radius: 5px;
            position: relative;
            overflow: hidden;
        }}
        .progress {{
            height: 100%;
            background-color: #2ecc71;
            width: {pass_rate}%;
        }}
        .severity-critical {{
            color: #fff;
            background-color: #c0392b;
            padding: 3px 7px;
            border-radius: 3px;
        }}
        .severity-high {{
            color: #fff;
            background-color: #e67e22;
            padding: 3px 7px;
            border-radius: 3px;
        }}
        .severity-medium {{
            color: #fff;
            background-color: #f1c40f;
            padding: 3px 7px;
            border-radius: 3px;
        }}
        .severity-low {{
            color: #fff;
            background-color: #27ae60;
            padding: 3px 7px;
            border-radius: 3px;
        }}
        .status-passed {{
            color: #27ae60;
            font-weight: bold;
        }}
        .status-failed {{
            color: #c0392b;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }}
        th, td {{
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .details {{
            margin-top: 10px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
            display: none;
        }}
        .show-details {{
            color: #3498db;
            cursor: pointer;
            text-decoration: underline;
        }}
        .cve-link {{
            color: #3498db;
            text-decoration: none;
        }}
        .cve-link:hover {{
            text-decoration: underline;
        }}
        .remediation {{
            margin-top: 10px;
            padding: 15px;
            background-color: #edf7ed;
            border-left: 5px solid #27ae60;
            border-radius: 5px;
        }}
        pre {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            overflow: auto;
        }}
        footer {{
            margin-top: 50px;
            padding: 20px;
            text-align: center;
            background-color: #f8f9fa;
            border-radius: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Audit Report</h1>
            <p>Generated on {timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Scan ID: {scan_id}</p>
        </div>
        
        <h2>System Information</h2>
        <table>
            <tr>
                <th>Operating System</th>
                <td>{platform_info.get('os', 'Unknown')}</td>
            </tr>
            <tr>
                <th>Version</th>
                <td>{platform_info.get('version', 'Unknown')}</td>
            </tr>
            <tr>
                <th>Hostname</th>
                <td>{platform_info.get('hostname', 'Unknown')}</td>
            </tr>
        </table>
        
        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="summary-box">
                <h3>Overall Status</h3>
                <div class="progress-bar">
                    <div class="progress"></div>
                </div>
                <p>{passed_checks} of {total_checks} checks passed ({pass_rate:.1f}%)</p>
            </div>
            <div class="summary-box">
                <h3>Issues by Severity</h3>
                <p><span class="severity-critical">Critical</span>: {severity_counts['critical']}</p>
                <p><span class="severity-high">High</span>: {severity_counts['high']}</p>
                <p><span class="severity-medium">Medium</span>: {severity_counts['medium']}</p>
                <p><span class="severity-low">Low</span>: {severity_counts['low']}</p>
            </div>
        </div>
        
        <h2>Failed Checks</h2>
"""

        # Add failed checks
        failed_checks = {k: v for k, v in results.items() if not v.get("passed", False)}
        if failed_checks:
            html += """<table>
            <tr>
                <th>Check</th>
                <th>Severity</th>
                <th>Details</th>
                <th>CVEs</th>
            </tr>
"""
            for check_id, result in failed_checks.items():
                title = result.get("title", check_id)
                severity = result.get("severity", "medium").lower()
                details = result.get("details", {})
                cve_ids = result.get("cve_ids", [])
                
                # Format details as HTML
                details_html = "<ul>"
                for key, value in details.items():
                    details_html += f"<li><strong>{key}:</strong> {value}</li>"
                details_html += "</ul>"
                
                # Format CVEs as links
                cve_html = ""
                if cve_ids:
                    cve_html = ", ".join([f'<a href="https://nvd.nist.gov/vuln/detail/{cve}" class="cve-link" target="_blank">{cve}</a>' for cve in cve_ids])
                else:
                    cve_html = "None"
                
                # Add the check to the table
                html += f"""<tr>
                <td>{title}</td>
                <td><span class="severity-{severity}">{severity.upper()}</span></td>
                <td>{details_html}</td>
                <td>{cve_html}</td>
            </tr>
"""
            html += "</table>"
        else:
            html += "<p>No failed checks. Your system is secure!</p>"
        
        # Add passed checks
        html += "<h2>Passed Checks</h2>"
        passed_checks = {k: v for k, v in results.items() if v.get("passed", True)}
        if passed_checks:
            html += """<table>
            <tr>
                <th>Check</th>
                <th>Severity</th>
                <th>Status</th>
            </tr>
"""
            for check_id, result in passed_checks.items():
                title = result.get("title", check_id)
                severity = result.get("severity", "medium").lower()
                
                # Add the check to the table
                html += f"""<tr>
                <td>{title}</td>
                <td><span class="severity-{severity}">{severity.upper()}</span></td>
                <td class="status-passed">PASSED</td>
            </tr>
"""
            html += "</table>"
        else:
            html += "<p>No passed checks. Your system needs immediate attention!</p>"
        
        # Add footer and JavaScript
        html += """
        <footer>
            <p>Generated by Security Auditor Tool</p>
        </footer>
    </div>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Toggle details visibility
            const showDetails = document.querySelectorAll('.show-details');
            showDetails.forEach(function(element) {
                element.addEventListener('click', function() {
                    const details = this.nextElementSibling;
                    if (details.style.display === 'block') {
                        details.style.display = 'none';
                        this.textContent = 'Show Details';
                    } else {
                        details.style.display = 'block';
                        this.textContent = 'Hide Details';
                    }
                });
            });
        });
    </script>
</body>
</html>
"""
        return html
    
    def _create_text_content(self, scan_result: dict) -> str:
        """Create plain text report content from scan results."""
        # Extract scan info
        scan_id = scan_result['scan_id']
        timestamp = datetime.fromisoformat(scan_result['timestamp'])
        platform_info = scan_result['platform_info']
        results = scan_result['results']
        
        # Calculate statistics
        total_checks = scan_result['check_count']
        passed_checks = scan_result['passed_count']
        failed_checks = scan_result['failed_count']
        pass_rate = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        # Count issues by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for check_id, result in results.items():
            if not result.get("passed", False):
                severity = result.get("severity", "medium").lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        # Begin text content
        text = f"""SECURITY AUDIT REPORT
=====================
Generated on: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Scan ID: {scan_id}

SYSTEM INFORMATION
------------------
Operating System: {platform_info.get('os', 'Unknown')}
Version: {platform_info.get('version', 'Unknown')}
Hostname: {platform_info.get('hostname', 'Unknown')}

EXECUTIVE SUMMARY
----------------
Overall Status: {passed_checks} of {total_checks} checks passed ({pass_rate:.1f}%)

Issues by Severity:
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}

"""
        
        # Add failed checks
        text += "FAILED CHECKS\n-------------\n"
        failed_checks = {k: v for k, v in results.items() if not v.get("passed", False)}
        if failed_checks:
            for check_id, result in failed_checks.items():
                title = result.get("title", check_id)
                severity = result.get("severity", "medium").upper()
                details = result.get("details", {})
                cve_ids = result.get("cve_ids", [])
                
                text += f"{title} (Severity: {severity})\n"
                text += "-" * len(f"{title} (Severity: {severity})") + "\n"
                
                # Add details
                text += "Details:\n"
                for key, value in details.items():
                    text += f"  * {key}: {value}\n"
                
                # Add CVEs
                if cve_ids:
                    text += "CVEs: " + ", ".join(cve_ids) + "\n"
                else:
                    text += "CVEs: None\n"
                
                text += "\n"
        else:
            text += "No failed checks. Your system is secure!\n\n"
        
        # Add passed checks
        text += "PASSED CHECKS\n-------------\n"
        passed_checks = {k: v for k, v in results.items() if v.get("passed", True)}
        if passed_checks:
            for check_id, result in passed_checks.items():
                title = result.get("title", check_id)
                severity = result.get("severity", "medium").upper()
                
                text += f"{title} (Severity: {severity}) - PASSED\n"
            text += "\n"
        else:
            text += "No passed checks. Your system needs immediate attention!\n\n"
        
        # Add footer
        text += """
Generated by Security Auditor Tool
"""
        return text
    
    def _create_comparison_html(self, old_scan: dict, new_scan: dict, comparison: dict) -> str:
        """Create HTML comparison report content."""
        # Extract scan info
        old_scan_id = old_scan['scan_id']
        old_timestamp = datetime.fromisoformat(old_scan['timestamp'])
        new_scan_id = new_scan['scan_id']
        new_timestamp = datetime.fromisoformat(new_scan['timestamp'])
        
        # Calculate statistics
        old_passed = old_scan['passed_count']
        old_total = old_scan['check_count']
        old_rate = (old_passed / old_total * 100) if old_total > 0 else 0
        
        new_passed = new_scan['passed_count']
        new_total = new_scan['check_count']
        new_rate = (new_passed / new_total * 100) if new_total > 0 else 0
        
        # Begin HTML content
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Comparison Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        h1, h2, h3, h4 {{
            color: #2c3e50;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background-color: #34495e;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
        }}
        .comparison-table {{
            width: 100%;
            margin-bottom: 30px;
        }}
        .comparison-table td {{
            width: 50%;
            padding: 20px;
            vertical-align: top;
        }}
        .summary-box {{
            padding: 15px;
            margin-bottom: 20px;
            background-color: #f8f9fa;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .summary-box h3 {{
            margin-top: 0;
        }}
        .progress-bar {{
            height: 20px;
            background-color: #e74c3c;
            border-radius: 5px;
            position: relative;
            overflow: hidden;
        }}
        .progress {{
            height: 100%;
            background-color: #2ecc71;
        }}
        .severity-critical {{
            color: #fff;
            background-color: #c0392b;
            padding: 3px 7px;
            border-radius: 3px;
        }}
        .severity-high {{
            color: #fff;
            background-color: #e67e22;
            padding: 3px 7px;
            border-radius: 3px;
        }}
        .severity-medium {{
            color: #fff;
            background-color: #f1c40f;
            padding: 3px 7px;
            border-radius: 3px;
        }}
        .severity-low {{
            color: #fff;
            background-color: #27ae60;
            padding: 3px 7px;
            border-radius: 3px;
        }}
        .status-improved {{
            color: #27ae60;
            font-weight: bold;
        }}
        .status-regressed {{
            color: #c0392b;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }}
        th, td {{
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
            text-align: left;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .section-header {{
            margin-top: 30px;
            padding: 10px;
            background-color: #f8f9fa;
            border-left: 5px solid #3498db;
        }}
        footer {{
            margin-top: 50px;
            padding: 20px;
            text-align: center;
            background-color: #f8f9fa;
            border-radius: 5px;
        }}
    </style>
