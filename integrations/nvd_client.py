#!/usr/bin/env python3
# NIST NVD API client

import json
import time
import logging
import requests
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nvd_client")

class NVDClient:
    """Client for the NIST National Vulnerability Database API."""
    
    # NVD API base URL
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None, cache_ttl: int = 3600):
        """
        Initialize the NVD API client.
        
        Args:
            api_key: Optional API key for higher rate limits
            cache_ttl: Time to live for cached responses in seconds
        """
        self.api_key = api_key
        self.cache_ttl = cache_ttl
        self.cache = {}
        self.last_request_time = 0
        
        # Rate limiting values
        self.rate_limit = 5 if api_key else 50  # Requests per 30 seconds
        self.rate_window = 30  # Seconds
        
    def _rate_limit(self):
        """Implement rate limiting according to NVD API guidelines."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        # Wait if we've made a request too recently
        if time_since_last < (self.rate_window / self.rate_limit):
            sleep_time = (self.rate_window / self.rate_limit) - time_since_last
            time.sleep(sleep_time)
            
        self.last_request_time = time.time()
        
    def get_cve(self, cve_id: str) -> Dict[str, Any]:
        """
        Get information for a specific CVE.
        
        Args:
            cve_id: The CVE ID (e.g., "CVE-2021-44228")
            
        Returns:
            dict: CVE information
        """
        # Check cache first
        if cve_id in self.cache:
            cache_time, data = self.cache[cve_id]
            if time.time() - cache_time < self.cache_ttl:
                return data
        
        # Implement rate limiting
        self._rate_limit()
        
        # Build request parameters
        params = {"cveId": cve_id}
        headers = {}
        
        if self.api_key:
            headers["apiKey"] = self.api_key
            
        try:
            response = requests.get(self.BASE_URL, params=params, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            
            # Cache the response
            self.cache[cve_id] = (time.time(), data)
            
            return data
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}: {e}")
            return {
                "error": str(e),
                "cve_id": cve_id
            }
    
    def search_cves(self, 
                   keyword: Optional[str] = None,
                   cpe_name: Optional[str] = None,
                   publish_start_date: Optional[str] = None,
                   publish_end_date: Optional[str] = None,
                   cvss_v3_severity: Optional[str] = None,
                   cvss_v2_severity: Optional[str] = None,
                   max_results: int = 20) -> Dict[str, Any]:
        """
        Search for CVEs with various filters.
        
        Args:
            keyword: Keyword to search for in CVE descriptions
            cpe_name: CPE name to filter by
            publish_start_date: Start date for CVE publication (YYYY-MM-DD)
            publish_end_date: End date for CVE publication (YYYY-MM-DD)
            cvss_v3_severity: CVSS v3 severity (LOW, MEDIUM, HIGH, CRITICAL)
            cvss_v2_severity: CVSS v2 severity (LOW, MEDIUM, HIGH)
            max_results: Maximum number of results to return
            
        Returns:
            dict: Search results
        """
        # Implement rate limiting
        self._rate_limit()
        
        # Build request parameters
        params = {"resultsPerPage": max_results}
        headers = {}
        
        if self.api_key:
            headers["apiKey"] = self.api_key
            
        if keyword:
            params["keywordSearch"] = keyword
            
        if cpe_name:
            params["cpeName"] = cpe_name
            
        if publish_start_date:
            params["pubStartDate"] = f"{publish_start_date}T00:00:00.000"
            
        if publish_end_date:
            params["pubEndDate"] = f"{publish_end_date}T23:59:59.999"
            
        if cvss_v3_severity:
            params["cvssV3Severity"] = cvss_v3_severity
            
        if cvss_v2_severity:
            params["cvssV2Severity"] = cvss_v2_severity
            
        try:
            response = requests.get(self.BASE_URL, params=params, headers=headers)
            response.raise_for_status()
            
            return response.json()
        except Exception as e:
            logger.error(f"Error searching CVEs: {e}")
            return {
                "error": str(e)
            }
    
    def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """
        Get detailed information for a CVE, extracting relevant fields.
        
        Args:
            cve_id: The CVE ID
            
        Returns:
            dict: Simplified CVE details
        """
        full_data = self.get_cve(cve_id)
        
        if "error" in full_data:
            return full_data
            
        try:
            # Extract the relevant vulnerability data
            vulnerabilities = full_data.get("vulnerabilities", [])
            if not vulnerabilities:
                return {"error": "No vulnerability data found", "cve_id": cve_id}
                
            cve_item = vulnerabilities[0].get("cve", {})
            
            # Extract details
            details = {
                "cve_id": cve_item.get("id", cve_id),
                "published": cve_item.get("published"),
                "last_modified": cve_item.get("lastModified"),
                "description": self._extract_description(cve_item),
                "severity": self._extract_severity(cve_item),
                "references": self._extract_references(cve_item),
                "configurations": self._extract_configurations(cve_item)
            }
            
            return details
        except Exception as e:
            logger.error(f"Error processing CVE {cve_id} details: {e}")
            return {
                "error": str(e),
                "cve_id": cve_id
            }
    
    def _extract_description(self, cve_item: Dict[str, Any]) -> str:
        """Extract the English description from a CVE item."""
        try:
            descriptions = cve_item.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    return desc.get("value", "")
            return ""
        except:
            return ""
    
    def _extract_severity(self, cve_item: Dict[str, Any]) -> Dict[str, Any]:
        """Extract CVSS severity information from a CVE item."""
        metrics = cve_item.get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if "cvssMetricV31" in metrics else {}
        cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {}) if "cvssMetricV2" in metrics else {}
        
        return {
            "cvss_v3": {
                "base_score": cvss_v3.get("baseScore"),
                "severity": cvss_v3.get("baseSeverity")
            },
            "cvss_v2": {
                "base_score": cvss_v2.get("baseScore"),
                "severity": cvss_v2.get("severity")
            }
        }
    
    def _extract_references(self, cve_item: Dict[str, Any]) -> List[str]:
        """Extract reference URLs from a CVE item."""
        references = []
        try:
            refs = cve_item.get("references", [])
            for ref in refs:
                url = ref.get("url")
                if url:
                    references.append(url)
            return references
        except:
            return []
    
    def _extract_configurations(self, cve_item: Dict[str, Any]) -> List[str]:
        """Extract affected configurations from a CVE item."""
        configurations = []
        try:
            configs = cve_item.get("configurations", [])
            for config in configs:
                nodes = config.get("nodes", [])
                for node in nodes:
                    cpe_match = node.get("cpeMatch", [])
                    for cpe in cpe_match:
                        criteria = cpe.get("criteria")
                        if criteria:
                            configurations.append(criteria)
            return configurations
        except:
            return []
            
    def map_security_issues_to_cves(self, issues: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Map security issues to relevant CVEs.
        
        Args:
            issues: Dictionary of security issues from a scan
            
        Returns:
            dict: Mapping of issue IDs to relevant CVEs
        """
        mappings = {}
        
        for check_id, issue in issues.items():
            if issue.get("passed", True):
                continue  # Skip passed checks
                
            # Get CVE IDs from the issue
            cve_ids = issue.get("cve_ids", [])
            
            # If there are explicit CVE IDs, fetch details for those
            if cve_ids:
                mappings[check_id] = []
                for cve_id in cve_ids:
                    details = self.get_cve_details(cve_id)
                    if "error" not in details:
                        mappings[check_id].append(details)
            else:
                # Search for relevant CVEs based on issue keywords
                title = issue.get("title", "")
                description = issue.get("description", "")
                keywords = f"{title} {description}"
                
                # Search for CVEs related to this issue
                search_results = self.search_cves(keyword=keywords, max_results=5)
                
                if "error" not in search_results:
                    vulnerabilities = search_results.get("vulnerabilities", [])
                    mappings[check_id] = []
                    
                    for vuln in vulnerabilities:
                        cve = vuln.get("cve", {})
                        cve_id = cve.get("id")
                        if cve_id:
                            details = self.get_cve_details(cve_id)
                            if "error" not in details:
                                mappings[check_id].append(details)
        
        return mappings
    def test_connection(self) -> bool:
        """
        Test connectivity to the NVD API by making a minimal request.
        Returns True if the API is reachable (HTTP 200), False otherwise.
        """
        try:
            # Respect NVD rate limiting
            self._rate_limit()
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key

            # Make a minimal request (1 result)
            response = requests.get(
                self.BASE_URL,
                params={"resultsPerPage": 1},
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"NVD API connection test failed: {e}")
            return False
