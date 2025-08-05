#!/usr/bin/env python3
"""
PhishDetector - Core phishing detection functionality.

This module provides the main PhishDetector class that implements various
detection methods including URL analysis, API checks, and domain validation.

Author: 0x4hm3d
Version: 2.0
"""

import json
import random
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
from urllib.parse import urlparse
import logging

import requests
import whois
from bs4 import BeautifulSoup as bsoup
from PIL import Image
from rich.table import Table
from rich import print as printc


class PhishDetectorError(Exception):
    """Base exception for PhishDetector errors."""
    pass


class InvalidURLError(PhishDetectorError):
    """Raised when an invalid URL is provided."""
    pass


class APIError(PhishDetectorError):
    """Raised when API calls fail."""
    pass


class FileNotFoundError(PhishDetectorError):
    """Raised when required database files are not found."""
    pass


class PhishDetector:
    """
    A comprehensive phishing detection tool that analyzes URLs for potential threats.
    
    This class provides multiple detection methods including:
    - URL redirection analysis
    - Google Safe Browsing checks
    - Domain reputation checks
    - API-based analysis (VirusTotal, URLScan.io, AbuseIPDB)
    - WHOIS lookups
    - Screenshot capture
    """
    
    def __init__(self, url: str, db_path: Optional[Path] = None) -> None:
        """
        Initialize the PhishDetector with a target URL.
        
        Args:
            url: The URL to analyze for phishing threats
            db_path: Optional path to database directory (defaults to ./db/)
            
        Raises:
            InvalidURLError: If the provided URL is invalid
            FileNotFoundError: If required database files are missing
        """
        self.logger = logging.getLogger(__name__)
        self.db_path = db_path or Path("db")
        
        # Validate and set URL
        if not self._is_valid_url(url):
            raise InvalidURLError(f"Invalid URL specified: {url}")
            
        self.url = url
        self.defanged_url = self._get_defanged_url(self.url)
        self.expanded_url = ""
        self.target_ip_address = "0.0.0.0"
        self.servers: List[Dict[str, str]] = []
        self.target_webpage_screenshot = ""
        
        # Validate database files
        self._validate_database_files()
        
        # Load user agents for requests
        self._user_agents = self._load_user_agents()
        
    def _is_valid_url(self, url: str) -> bool:
        """
        Validate if the provided URL is properly formatted.
        
        Args:
            url: URL string to validate
            
        Returns:
            True if URL is valid, False otherwise
        """
        try:
            parsed = urlparse(url)
            return (
                parsed.scheme in ('http', 'https') and
                parsed.netloc and
                not self._get_domain_name(url).replace(".", "").isdigit()
            )
        except Exception:
            return False
    
    def _validate_database_files(self) -> None:
        """
        Validate that all required database files exist.
        
        Raises:
            FileNotFoundError: If any required database file is missing
        """
        required_files = [
            "user_agents.db",
            "ip_tracking_domains.json", 
            "url_shortener_domains.db"
        ]
        
        for filename in required_files:
            file_path = self.db_path / filename
            if not file_path.exists():
                raise FileNotFoundError(f"Required database file not found: {file_path}")
    
    def _load_user_agents(self) -> List[str]:
        """
        Load user agents from database file.
        
        Returns:
            List of user agent strings
            
        Raises:
            FileNotFoundError: If user agents file cannot be loaded
        """
        try:
            user_agents_file = self.db_path / "user_agents.db"
            with open(user_agents_file, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            raise FileNotFoundError(f"Failed to load user agents: {e}")
    
    def get_user_agent(self) -> str:
        """
        Get a random user agent string.
        
        Returns:
            Random user agent string
        """
        return random.choice(self._user_agents)
    
    def _get_defanged_url(self, url: str) -> str:
        """
        Convert URL to defanged format for safe display.
        
        Args:
            url: Original URL
            
        Returns:
            Defanged URL string
        """
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.replace("https", "hxxps").replace("http", "hxxp")
            netloc = parsed.netloc.replace(".", "[.]")
            path = parsed.path or "/"
            return f"{scheme}[://]{netloc}{path}"
        except Exception:
            return url.replace(".", "[.]").replace("://", "[://]")
    
    def _get_domain_name(self, url: str) -> str:
        """
        Extract domain name from URL.
        
        Args:
            url: URL to extract domain from
            
        Returns:
            Domain name string
        """
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            # Fallback to original method for compatibility
            url_parts = url.split('/')
            return url_parts[2] if len(url_parts) > 2 else url
    
    def _make_request(self, url: str, method: str = 'GET', **kwargs) -> requests.Response:
        """
        Make HTTP request with proper headers and error handling.
        
        Args:
            url: URL to request
            method: HTTP method (GET, POST, etc.)
            **kwargs: Additional arguments for requests
            
        Returns:
            Response object
            
        Raises:
            APIError: If request fails
        """
        headers = kwargs.pop('headers', {})
        headers.setdefault('User-Agent', self.get_user_agent())
        
        try:
            response = requests.request(method, url, headers=headers, timeout=30, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            raise APIError(f"Request failed for {url}: {e}")
    
    def get_url_redirections(self, verbosity: bool = False) -> None:
        """
        Analyze URL redirections using iplogger.org service.
        
        Args:
            verbosity: If True, display detailed redirection information
        """
        try:
            headers = {
                'Accept-Encoding': 'gzip, deflate, br',
                'User-Agent': self.get_user_agent(),
                'Referer': 'https://iplogger.org/',
                'DNT': '1',
                'Upgrade-Insecure-Requests': '1',
            }
            
            ip_logger_url_checker = "https://iplogger.org/url-checker/"
            
            with requests.Session() as session:
                # Initial request to get cookies
                response = session.get(ip_logger_url_checker, headers=headers, timeout=30)
                
                # Update headers with cookies and cache info
                if 'Set-Cookie' in response.headers:
                    headers['Cookie'] = response.headers['Set-Cookie']
                if 'Cache-Control' in response.headers:
                    headers['Cache-Control'] = response.headers['Cache-Control']
                if 'Last-Modified' in response.headers:
                    headers['If-Modified-Since'] = response.headers['Last-Modified']
                
                # Make request with target URL
                params = {"url": self.url}
                response = session.get(ip_logger_url_checker, headers=headers, params=params, timeout=30)
                
                if response.ok:
                    self._parse_redirection_response(response.content, verbosity)
                else:
                    self.logger.warning(f"Failed to get redirection info: HTTP {response.status_code}")
                    
        except Exception as e:
            self.logger.error(f"Error analyzing URL redirections: {e}")
            printc("[red3][-][/red3] Failed to analyze URL redirections")
    
    def _parse_redirection_response(self, content: bytes, verbosity: bool) -> None:
        """
        Parse the HTML response from iplogger.org to extract redirection info.
        
        Args:
            content: HTML content from response
            verbosity: If True, display detailed information
        """
        try:
            soup = bsoup(content, 'html.parser')
            servers_info = soup.find_all("div", class_="server-info")
            
            self.servers = []
            
            for server_info in servers_info:
                server_dict = self._extract_server_info(server_info)
                if server_dict:
                    self.servers.append(server_dict)
            
            self._display_redirection_info(verbosity)
            
        except Exception as e:
            self.logger.error(f"Error parsing redirection response: {e}")
    
    def _extract_server_info(self, server_info) -> Optional[Dict[str, str]]:
        """
        Extract server information from HTML element.
        
        Args:
            server_info: BeautifulSoup element containing server info
            
        Returns:
            Dictionary with server information or None if extraction fails
        """
        try:
            server_items = server_info.find_all("div", class_="server-item")
            server_antivirus = server_info.find("div", class_="server-antivirus")
            server_next = server_info.find("div", class_="server-next")
            
            server_dict = {}
            
            for server_item in server_items:
                item_info = [item for item in server_item if item != "\n"]
                if len(item_info) >= 2:
                    key = item_info[0].string if hasattr(item_info[0], 'string') else str(item_info[0])
                    
                    if key == "Host":
                        value = item_info[-1].string if hasattr(item_info[-1], 'string') else str(item_info[-1])
                        server_dict[key] = value
                        self.expanded_url = value
                    elif key == "IP address":
                        if hasattr(item_info[-1], 'contents') and len(item_info[-1].contents) > 1:
                            value = item_info[-1].contents[-2].string
                        else:
                            value = str(item_info[-1])
                        server_dict[key] = value
                        self.target_ip_address = value
                    else:
                        value = item_info[-1].string if hasattr(item_info[-1], 'string') else str(item_info[-1])
                        server_dict[key] = value
            
            # Add status code and antivirus info
            if server_next and hasattr(server_next, 'contents') and len(server_next.contents) > 1:
                server_dict["Status code"] = server_next.contents[1].string
            
            if server_antivirus and hasattr(server_antivirus, 'contents') and len(server_antivirus.contents) > 1:
                server_dict["Google Safe Browsing Database"] = server_antivirus.contents[1].string
            
            return server_dict
            
        except Exception as e:
            self.logger.error(f"Error extracting server info: {e}")
            return None
    
    def _display_redirection_info(self, verbosity: bool) -> None:
        """
        Display redirection information in formatted tables.
        
        Args:
            verbosity: If True, show detailed information
        """
        number_of_redirections = len(self.servers)
        
        if number_of_redirections > 1:
            if verbosity:
                self._display_detailed_redirections()
            else:
                self._display_simple_redirections()
        else:
            printc('[red3][-][/red3] No redirection found!')
    
    def _display_detailed_redirections(self) -> None:
        """Display detailed redirection information in a table."""
        table = Table(title="ℝ 𝔼 𝔻 𝕀 ℝ 𝔼 ℂ 𝕋 𝕀 𝕆 ℕ 𝕊", show_lines=True)
        table.add_column("ID", justify="center")
        table.add_column("URL", justify="center", max_width=60)
        table.add_column("Status Code", justify="center")
        table.add_column("IP Address", justify="center")
        table.add_column("Country by IP", justify="center")
        
        for i, server in enumerate(self.servers):
            table.add_row(
                str(i + 1),
                server.get('Host', 'N/A'),
                server.get('Status code', 'N/A'),
                server.get('IP address', 'N/A'),
                server.get('Country by IP', 'N/A')
            )
        
        printc(table)
    
    def _display_simple_redirections(self) -> None:
        """Display simple redirection information."""
        table = Table(title="ℝ 𝔼 𝔻 𝕀 ℝ 𝔼 ℂ 𝕋 𝕀 𝕆 ℕ 𝕊", show_lines=True)
        table.add_column("Source URL", justify="center", max_width=60)
        table.add_column("Source Domain", justify="center")
        table.add_column("Destination URL", justify="center", max_width=60)
        table.add_column("Destination Domain", justify="center")
        
        table.add_row(
            self.url,
            self._get_domain_name(self.url),
            self.expanded_url,
            self._get_domain_name(self.expanded_url)
        )
        
        printc(table)
    
    def check_google_safe_browsing(self) -> None:
        """Check Google Safe Browsing status from redirection analysis."""
        if not self.servers:
            printc("[red3][-][/red3] No redirection data available for Safe Browsing check")
            return
        
        try:
            last_server = self.servers[-1]
            safe_browsing_result = last_server.get('Google Safe Browsing Database', '')
            
            if "no such URL in our anti-virus databases" in safe_browsing_result:
                printc("[spring_green2][+][/spring_green2] No threats found in Google Safe Browsing")
            else:
                target_url = self.expanded_url.replace("https://", "").replace("http://", "")
                printc(f"[gold1][!][/gold1] [gold1]{target_url}[/gold1]: [red3 b]{safe_browsing_result}[/red3 b]")
                
        except Exception as e:
            self.logger.error(f"Error checking Google Safe Browsing: {e}")
            printc("[red3][-][/red3] Error checking Google Safe Browsing")
    
    def check_tracking_domain_name(self) -> None:
        """Check if the domain is a known IP tracking domain."""
        try:
            target_domain = self._get_domain_name(self.url)
            tracking_domains_file = self.db_path / "ip_tracking_domains.json"
            
            with open(tracking_domains_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for provider, domains in data.items():
                if isinstance(domains, list):
                    if target_domain in domains:
                        printc(f"[gold1][!][/gold1] [gold1]{target_domain}[/gold1] is an IP tracking domain owned by [gold1]{provider}[/gold1]!")
                        return
                elif isinstance(domains, str):
                    if domains == target_domain:
                        printc(f"[gold1][!][/gold1] [gold1]{target_domain}[/gold1] is an IP tracking domain owned by [gold1]{provider}[/gold1]!")
                        return
            
            printc("[spring_green2][+][/spring_green2] Domain not found in IP tracking database")
            
        except Exception as e:
            self.logger.error(f"Error checking tracking domains: {e}")
            printc("[red3][-][/red3] Error checking IP tracking domains")
    
    def check_url_shortener_domain(self) -> None:
        """Check if the domain is a known URL shortener."""
        try:
            target_domain = self._get_domain_name(self.url)
            shortener_domains_file = self.db_path / "url_shortener_domains.db"
            
            with open(shortener_domains_file, 'r', encoding='utf-8') as f:
                shortener_domains = [line.strip() for line in f.readlines()]
            
            if target_domain in shortener_domains:
                printc(f"[gold1][!][/gold1] [gold1]{target_domain}[/gold1] found in URL shortener domains database!")
                printc(f"[gold1][!][/gold1] [red3]{self.defanged_url}[/red3] is a [gold1]shortened[/gold1] URL!")
            else:
                printc("[spring_green2][+][/spring_green2] Domain not found in URL shortener database")
                
        except Exception as e:
            self.logger.error(f"Error checking URL shortener domains: {e}")
            printc("[red3][-][/red3] Error checking URL shortener domains")
    
    def check_virustotal(self, target_url: str, api_key: str, verbosity: bool = False) -> None:
        """
        Check URL against VirusTotal database.
        
        Args:
            target_url: URL to check
            api_key: VirusTotal API key
            verbosity: If True, show detailed results
        """
        try:
            url = "https://www.virustotal.com/api/v3/urls"
            payload = f"url={target_url}"
            headers = {
                "accept": "application/json",
                "x-apikey": api_key,
                "content-type": "application/x-www-form-urlencoded"
            }
            
            response = self._make_request(url, method='POST', data=payload, headers=headers)
            
            if response.status_code == 200:
                self._process_virustotal_response(response.json(), headers, verbosity)
            else:
                printc(f"[red3][-][/red3] VirusTotal API error: {response.status_code}")
                
        except APIError as e:
            printc(f"[red3][-][/red3] VirusTotal API error: {e}")
        except Exception as e:
            self.logger.error(f"Error checking VirusTotal: {e}")
            printc("[red3][-][/red3] Error checking VirusTotal")
    
    def _process_virustotal_response(self, response_data: Dict[str, Any], headers: Dict[str, str], verbosity: bool) -> None:
        """
        Process VirusTotal API response and display results.
        
        Args:
            response_data: JSON response from VirusTotal
            headers: Request headers for follow-up requests
            verbosity: If True, show detailed results
        """
        try:
            url_scan_link = response_data['data']['links']['self']
            max_wait_time = 60
            wait_time = 10
            elapsed_time = 0
            
            while elapsed_time < max_wait_time:
                try:
                    analysis_response = self._make_request(url_scan_link, headers=headers)
                    analysis_data = analysis_response.json()
                    
                    if 'data' in analysis_data and 'attributes' in analysis_data['data']:
                        self._display_virustotal_results(analysis_data, verbosity)
                        break
                    else:
                        printc(f"[gold1][!][/gold1] Scan in progress. Waiting {wait_time} seconds...")
                        time.sleep(wait_time)
                        elapsed_time += wait_time
                        wait_time = 5
                        
                except APIError:
                    printc(f"[gold1][!][/gold1] Scan in progress. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    elapsed_time += wait_time
                    wait_time = 5
            
            if elapsed_time >= max_wait_time:
                printc("[red3][-][/red3] VirusTotal scan timeout")
                
        except Exception as e:
            self.logger.error(f"Error processing VirusTotal response: {e}")
            printc("[red3][-][/red3] Error processing VirusTotal results")
    
    def _display_virustotal_results(self, analysis_data: Dict[str, Any], verbosity: bool) -> None:
        """
        Display VirusTotal analysis results.
        
        Args:
            analysis_data: Analysis data from VirusTotal
            verbosity: If True, show detailed results
        """
        try:
            attributes = analysis_data['data']['attributes']
            stats = attributes['stats']
            results = attributes['results']
            url_info_id = analysis_data['meta']['url_info']['id']
            
            total_vendors = len(results)
            malicious_count = stats['malicious']
            
            if malicious_count > 0:
                printc(f"[gold1][!][/gold1] [red3]{malicious_count} security vendors flagged this URL as malicious[/red3]")
            else:
                printc("[spring_green2][+][/spring_green2] No security vendors flagged this URL as malicious")
            
            printc(f"[spring_green2][+][/spring_green2] Security vendors' analysis\n{'-' * 32}")
            
            # Display statistics
            for stat, value in stats.items():
                printc(f"[gold1][!][/gold1] {stat}: {value}/{total_vendors}")
            
            # Display detailed results if verbose and malicious
            if verbosity and malicious_count > 0:
                self._display_virustotal_details(results)
            
            # Display report URL
            report_url = f"https://www.virustotal.com/gui/url/{url_info_id}"
            printc("[spring_green2][+][/spring_green2] For more information, check the link below ↓")
            printc(f"[spring_green2][+][/spring_green2] {report_url}")
            
        except Exception as e:
            self.logger.error(f"Error displaying VirusTotal results: {e}")
    
    def _display_virustotal_details(self, results: Dict[str, Any]) -> None:
        """
        Display detailed VirusTotal results in a table.
        
        Args:
            results: Detailed results from VirusTotal
        """
        table = Table(title="𝔻 𝔼 𝕋 𝔸 𝕀 𝕃 𝕊", show_lines=True)
        table.add_column("VENDOR", justify="center", max_width=60)
        table.add_column("RESULT", justify="center")
        table.add_column("METHOD", justify="center")
        
        for vendor, result in results.items():
            if result.get('category') == "malicious":
                table.add_row(
                    vendor,
                    result.get('result', 'N/A'),
                    result.get('method', 'N/A')
                )
        
        printc(table)
    
    def check_urlscan_io(self, target_url: str, api_key: str, verbosity: bool = False) -> None:
        """
        Check URL using URLScan.io service.
        
        Args:
            target_url: URL to scan
            api_key: URLScan.io API key
            verbosity: If True, show detailed results
        """
        try:
            headers = {'API-Key': api_key, 'Content-Type': 'application/json'}
            data = {"url": target_url, "visibility": "unlisted"}
            
            response = self._make_request(
                'https://urlscan.io/api/v1/scan/',
                method='POST',
                headers=headers,
                data=json.dumps(data)
            )
            
            if response.status_code == 200:
                self._process_urlscan_response(response.json(), verbosity)
            elif response.status_code == 400:
                error_msg = response.json().get('message', 'Bad request')
                printc(f"[red3][-][/red3] URLScan.io error: {error_msg}")
            elif response.status_code == 429:
                printc("[red3][!][/red3] URLScan.io rate-limit exceeded!")
                printc("[gold1][!][/gold1] More info: https://urlscan.io/docs/api/#ratelimit")
            else:
                printc(f"[red3][-][/red3] URLScan.io API error: {response.status_code}")
                
        except APIError as e:
            printc(f"[red3][-][/red3] URLScan.io API error: {e}")
        except Exception as e:
            self.logger.error(f"Error checking URLScan.io: {e}")
            printc("[red3][-][/red3] Error checking URLScan.io")
    
    def _process_urlscan_response(self, response_data: Dict[str, Any], verbosity: bool) -> None:
        """
        Process URLScan.io response and wait for results.
        
        Args:
            response_data: Initial response from URLScan.io
            verbosity: If True, show detailed results
        """
        try:
            result_api_url = response_data['api']
            max_wait_time = 120
            wait_time = 10
            elapsed_time = 0
            
            while elapsed_time < max_wait_time:
                try:
                    result_response = self._make_request(result_api_url)
                    result_data = result_response.json()
                    
                    if 'verdicts' in result_data:
                        self._display_urlscan_results(result_data, verbosity)
                        break
                        
                except APIError:
                    printc(f"[gold1][!][/gold1] Scan in progress. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    elapsed_time += wait_time
                    wait_time = 5
            
            if elapsed_time >= max_wait_time:
                printc("[red3][-][/red3] URLScan.io scan timeout")
                
        except Exception as e:
            self.logger.error(f"Error processing URLScan.io response: {e}")
    
    def _display_urlscan_results(self, result_data: Dict[str, Any], verbosity: bool) -> None:
        """
        Display URLScan.io results.
        
        Args:
            result_data: Results from URLScan.io
            verbosity: If True, show detailed results
        """
        try:
            # Store screenshot URL
            if 'task' in result_data and 'screenshotURL' in result_data['task']:
                self.target_webpage_screenshot = result_data['task']['screenshotURL']
            
            verdicts = result_data.get('verdicts', {})
            verdict_overall = verdicts.get('overall', {})
            verdict_urlscan = verdicts.get('urlscan', {})
            
            overall_score = verdict_overall.get('score', 0)
            
            if overall_score > 0:
                printc(f"\n[spring_green2][+][/spring_green2] Verdict Overall\n{'-' * 20}")
                printc(f"[spring_green2][+][/spring_green2] Time: {result_data['task']['time']}")
                
                for prop, value in verdict_overall.items():
                    if isinstance(value, list) and value:
                        printc(f"[gold1][!][/gold1] {prop}: {value[0]}")
                    else:
                        printc(f"[gold1][!][/gold1] {prop}: {value}")
                
                if verbosity:
                    self._display_urlscan_details(verdict_urlscan)
            else:
                printc(f"\n[gold1][!][/gold1] Verdict URLScan\n{'-' * 20}")
                printc(f"[gold1][!][/gold1] Score: {verdict_urlscan.get('score', 0)}")
                printc(f"[gold1][!][/gold1] Malicious: {verdict_urlscan.get('malicious', False)}")
                printc(f"\n[gold1][!][/gold1] Verdict Overall\n{'-' * 20}")
                printc(f"[gold1][!][/gold1] Score: {overall_score}")
                printc(f"[gold1][!][/gold1] Malicious: {verdict_overall.get('malicious', False)}")
            
            # Display report URL
            if 'task' in result_data and 'reportURL' in result_data['task']:
                printc("[spring_green2][+][/spring_green2] For more information, check the link below ↓")
                printc(f"[spring_green2][+][/spring_green2] {result_data['task']['reportURL']}")
                
        except Exception as e:
            self.logger.error(f"Error displaying URLScan.io results: {e}")
    
    def _display_urlscan_details(self, verdict_urlscan: Dict[str, Any]) -> None:
        """
        Display detailed URLScan.io verdict information.
        
        Args:
            verdict_urlscan: URLScan verdict data
        """
        printc(f"\n[spring_green2][+][/spring_green2] Verdict URLScan\n{'-' * 20}")
        
        for prop, value in verdict_urlscan.items():
            if isinstance(value, list) and value:
                if prop == 'brands' and isinstance(value[0], dict):
                    for brand_key, brand_value in value[0].items():
                        if brand_value:
                            printc(f"[gold1][!][/gold1] Brand {brand_key}: {brand_value}")
                        else:
                            printc(f"[red3][-][/red3] Brand {brand_key}: N/A")
                else:
                    printc(f"[gold1][!][/gold1] {prop}: {value[0]}")
            else:
                if prop in ['score', 'malicious']:
                    printc(f"[gold1][!][/gold1] {prop}: {value}")
    
    def check_abuse_ip_db(self, ip_address: str, api_key: str, verbosity: bool = False) -> None:
        """
        Check IP address against AbuseIPDB.
        
        Args:
            ip_address: IP address to check
            api_key: AbuseIPDB API key
            verbosity: If True, show detailed results
        """
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': '365'
            }
            headers = {
                'Accept': 'application/json',
                'Key': api_key
            }
            
            response = self._make_request(url, params=params, headers=headers)
            
            if response.status_code == 200:
                self._display_abuseipdb_results(response.json(), verbosity)
            elif response.status_code == 401:
                error_detail = response.json().get('errors', [{}])[0].get('detail', 'Unauthorized')
                printc(f"[red3][-][/red3] AbuseIPDB error: {error_detail}")
                printc("[gold1][!][/gold1] Check documentation: https://github.com/0x4hm3d/PhishScanner/blob/main/README.md")
            else:
                printc(f"[red3][-][/red3] AbuseIPDB API error: {response.status_code}")
                
        except APIError as e:
            printc(f"[red3][-][/red3] AbuseIPDB API error: {e}")
        except Exception as e:
            self.logger.error(f"Error checking AbuseIPDB: {e}")
            printc("[red3][-][/red3] Error checking AbuseIPDB")
    
    def _display_abuseipdb_results(self, response_data: Dict[str, Any], verbosity: bool) -> None:
        """
        Display AbuseIPDB results.
        
        Args:
            response_data: Response data from AbuseIPDB
            verbosity: If True, show detailed results
        """
        try:
            ip_info = response_data.get('data', {})
            total_reports = ip_info.get('totalReports', 0)
            
            if total_reports > 0:
                ip_address = ip_info.get('ipAddress', 'Unknown')
                distinct_users = ip_info.get('numDistinctUsers', 0)
                confidence_score = ip_info.get('abuseConfidenceScore', 0)
                
                printc(f"[gold1][!][/gold1] [gold1]{ip_address}[/gold1] was found in Abuse IP DB!")
                printc(f"[gold1][!][/gold1] This IP was reported [gold1]{total_reports}[/gold1] times by [gold1]{distinct_users}[/gold1] distinct users.")
                printc(f"[gold1][!][/gold1] Confidence of Abuse is [gold1]{confidence_score}[/gold1]")
                
                if verbosity:
                    self._display_abuseipdb_details(ip_info, exclude_keys=['abuseConfidenceScore', 'numDistinctUsers', 'totalReports'])
                else:
                    self._display_abuseipdb_summary(ip_info)
            else:
                printc("[spring_green2][+][/spring_green2] IP address not found in AbuseIPDB")
                
        except Exception as e:
            self.logger.error(f"Error displaying AbuseIPDB results: {e}")
    
    def _display_abuseipdb_details(self, ip_info: Dict[str, Any], exclude_keys: List[str]) -> None:
        """Display detailed AbuseIPDB information."""
        for prop in sorted(ip_info.keys()):
            if prop not in exclude_keys:
                value = ip_info[prop]
                printc(f"[spring_green2][+][/spring_green2] {prop}: {value}")
    
    def _display_abuseipdb_summary(self, ip_info: Dict[str, Any]) -> None:
        """Display summary AbuseIPDB information."""
        summary_keys = ['isp', 'isTor', 'isWhiteListed', 'usageType', 'lastReportedAt']
        for prop in sorted(ip_info.keys()):
            if prop in summary_keys:
                value = ip_info[prop]
                printc(f"[spring_green2][+][/spring_green2] {prop}: {value}")
    
    def get_whois_info(self, target_ip_address: str, verbosity: bool = False) -> None:
        """
        Perform WHOIS lookup on IP address.
        
        Args:
            target_ip_address: IP address to lookup
            verbosity: If True, show detailed information
        """
        try:
            whois_info = whois.whois(target_ip_address)
            
            if not whois_info:
                printc("[red3][-][/red3] No WHOIS information available")
                return
            
            if verbosity:
                self._display_detailed_whois(whois_info)
            else:
                self._display_summary_whois(whois_info)
                
        except Exception as e:
            self.logger.error(f"Error getting WHOIS info: {e}")
            printc("[red3][-][/red3] Unable to retrieve WHOIS information")
    
    def _display_detailed_whois(self, whois_info: Dict[str, Any]) -> None:
        """Display detailed WHOIS information."""
        for key, value in whois_info.items():
            if key != "status":
                if isinstance(value, list):
                    if 'date' in key and value:
                        printc(f"[spring_green2][+][/spring_green2] {key.capitalize()}: {value[0]}")
                    elif value:
                        printc(f"[spring_green2][+][/spring_green2] {key.capitalize()}: {', '.join(map(str, value))}")
                    else:
                        printc(f"[red3][-][/red3] {key.capitalize()}: N/A")
                else:
                    if value is None:
                        printc(f"[red3][-][/red3] {key.capitalize()}: N/A")
                    else:
                        printc(f"[spring_green2][+][/spring_green2] {key.capitalize()}: {value}")
    
    def _display_summary_whois(self, whois_info: Dict[str, Any]) -> None:
        """Display summary WHOIS information."""
        summary_keys = ['name', 'emails', 'address', 'registrant_postal_code', 'registrar',
                       'creation_date', 'updated_date', 'expiration_date', 'country']
        
        for key, value in whois_info.items():
            if key in summary_keys:
                if isinstance(value, list):
                    if 'date' in key and value:
                        printc(f"[spring_green2][+][/spring_green2] {key.capitalize()}: {value[0]}")
                    elif value:
                        printc(f"[spring_green2][+][/spring_green2] {key.capitalize()}: {', '.join(map(str, value))}")
                    else:
                        printc(f"[red3][-][/red3] {key.capitalize()}: N/A")
                else:
                    if value is None:
                        printc(f"[red3][-][/red3] {key.capitalize()}: N/A")
                    else:
                        printc(f"[spring_green2][+][/spring_green2] {key.capitalize()}: {value}")
    
    def webpage_illustration(self, auto_display: bool = False) -> None:
        """
        Capture and optionally display webpage screenshot.
        
        Args:
            auto_display: If True, automatically display screenshot without prompting
        """
        try:
            screenshot_url = self._get_screenshot_url()
            
            if not screenshot_url:
                printc("[red3][-][/red3] Screenshot unavailable")
                return
            
            response = self._make_request(screenshot_url, stream=True)
            
            if response.status_code == 200:
                if auto_display or self._should_display_screenshot():
                    self._display_screenshot(response)
                else:
                    printc("[spring_green2][+][/spring_green2] Screenshot available but not displayed")
            else:
                printc("[red3][-][/red3] Screenshot unavailable")
                
        except Exception as e:
            self.logger.error(f"Error capturing screenshot: {e}")
            printc("[red3][-][/red3] Screenshot unavailable")
    
    def _get_screenshot_url(self) -> str:
        """Get screenshot URL from URLScan.io or PagePeeker."""
        if self.target_webpage_screenshot:
            return self.target_webpage_screenshot
        
        # Fallback to PagePeeker
        return f"https://api.pagepeeker.com/v2/thumbs.php?size=x&url={self.expanded_url or self.url}"
    
    def _should_display_screenshot(self) -> bool:
        """Ask user if they want to see the screenshot."""
        try:
            user_choice = input(f"Would you like to see a real-time screenshot of {self.defanged_url} [Yes/no]: ")
            return user_choice.lower() in ['', 'y', 'yes', 'yep', 'yeah', 'yay']
        except (EOFError, KeyboardInterrupt):
            return False
    
    def _display_screenshot(self, response: requests.Response) -> None:
        """Display the screenshot using PIL."""
        try:
            with Image.open(response.raw) as img:
                img.show()
                printc("[spring_green2][+][/spring_green2] Screenshot displayed successfully")
        except Exception as e:
            self.logger.error(f"Error displaying screenshot: {e}")
            printc("[red3][-][/red3] Error displaying screenshot")
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the analysis results.
        
        Returns:
            Dictionary containing analysis summary
        """
        return {
            'url': self.url,
            'defanged_url': self.defanged_url,
            'expanded_url': self.expanded_url,
            'target_ip': self.target_ip_address,
            'redirections_count': len(self.servers),
            'has_screenshot': bool(self.target_webpage_screenshot),
            'domain': self._get_domain_name(self.url)
        }
