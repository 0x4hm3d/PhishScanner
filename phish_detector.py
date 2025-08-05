#!/usr/bin/env python3
"""
PhishDetector - Core phishing detection functionality.

This module provides the main PhishDetector class that implements various
detection methods including URL analysis, API checks, and domain validation.

Author: 0x4hm3d
Version: 2.2 (Revised)
"""

import json
import random
import sys
import time
import socket
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
from urllib.parse import urlparse
import logging
from io import BytesIO

import requests
import whois
from whois.parser import PywhoisError
from bs4 import BeautifulSoup as bsoup
from PIL import Image
from rich.table import Table
from rich import print as printc
from datetime import datetime

# Constants for configurable timeouts
DEFAULT_REQUEST_TIMEOUT = 30
DEFAULT_API_WAIT_TIME = 10
DEFAULT_MAX_API_WAIT = 60
RATE_LIMIT_DELAY = 0.5  # Basic rate limiting delay in seconds

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
            FileNotFoundError: If required database files or directory are missing
        """
        self.logger = logging.getLogger(__name__)
        
        self.db_path = (Path(db_path).resolve() if db_path else Path("db").resolve())
        if not self.db_path.is_dir():
            raise FileNotFoundError(f"Database path {self.db_path} is not a directory or does not exist")
        
        if not self._is_valid_url(url):
            raise InvalidURLError(f"Invalid URL specified: {url}")
            
        self.url = url
        self.defanged_url = self._get_defanged_url(self.url)
        self.expanded_url = ""
        self.target_ip_address = "0.0.0.0"
        self.servers: List[Dict[str, str]] = []
        self.target_webpage_screenshot = ""
        
        self._validate_database_files()
        self._user_agents = self._load_user_agents()

    def _display_urlscan_results(self, result_data: Dict[str, Any], verbosity: bool) -> None:
        """Display URLScan.io results."""
        try:
            if 'task' in result_data and 'screenshotURL' in result_data['task']:
                self.target_webpage_screenshot = result_data['task']['screenshotURL']
            
            verdicts = result_data.get('verdicts', {})
            verdict_overall = verdicts.get('overall', {})
            verdict_urlscan = verdicts.get('urlscan', {})
            
            overall_score = verdict_overall.get('score', 0)
            
            if overall_score > 0:
                printc(f"\n[spring_green2][+][/spring_green2] Verdict Overall\n{'-' * 20}")
                printc(f"[spring_green2][+][/spring_green2] Time: {result_data.get('task', {}).get('time', 'N/A')}")
                
                for prop, value in verdict_overall.items():
                    printc(f"[gold1][!][/gold1] {prop}: {value[0] if isinstance(value, list) and value else value}")
                
                if verbosity:
                    self._display_urlscan_details(verdict_urlscan)
            else:
                printc(f"\n[gold1][!][/gold1] Verdict URLScan\n{'-' * 20}")
                printc(f"[gold1][!][/gold1] Score: {verdict_urlscan.get('score', 0)}")
                printc(f"[gold1][!][/gold1] Malicious: {verdict_urlscan.get('malicious', False)}")
                printc(f"\n[gold1][!][/gold1] Verdict Overall\n{'-' * 20}")
                printc(f"[gold1][!][/gold1] Score: {overall_score}")
                printc(f"[gold1][!][/gold1] Malicious: {verdict_overall.get('malicious', False)}")
            
            if 'task' in result_data and 'reportURL' in result_data['task']:
                printc("[spring_green2][+][/spring_green2] For more information, check the link below ↓")
                printc(f"[spring_green2][+][/spring_green2] {result_data['task']['reportURL']}")
                
        except Exception as e:
            self.logger.error(f"Error displaying URLScan.io results: {e}")
            printc(f"[red3][-][/red3] Error displaying URLScan.io results: {str(e)}")

    @staticmethod
    def _get_domain_name(url: str) -> str:
        """Extract domain name from URL."""
        if not url:
            return ""
        try:
            return urlparse(url).netloc
        except (ValueError, AttributeError):
            return ""

    def _is_valid_url(self, url: str) -> bool:
        """Validate if the provided URL is properly formatted."""
        try:
            parsed = urlparse(url)
            domain = PhishDetector._get_domain_name(url)
            return (
                parsed.scheme in ('http', 'https') and
                bool(domain) and
                not domain.replace(".", "").isdigit()
            )
        except (ValueError, AttributeError):
            self.logger.warning(f"Invalid URL format: {url}")
            return False
    
    def _validate_database_files(self) -> None:
        """Validate that all required database files exist."""
        required_files = ["user_agents.db", "ip_tracking_domains.json", "url_shortener_domains.db"]
        for filename in required_files:
            file_path = self.db_path / filename
            if not file_path.exists():
                raise FileNotFoundError(f"Required database file not found: {file_path}")
    
    def _load_user_agents(self) -> List[str]:
        """Load user agents from database file."""
        user_agents_file = self.db_path / "user_agents.db"
        try:
            with open(user_agents_file, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except (IOError, OSError) as e:
            raise FileNotFoundError(f"Failed to load user agents file: {e}")
    
    def get_user_agent(self) -> str:
        """Get a random user agent string."""
        return random.choice(self._user_agents)
    
    def _get_defanged_url(self, url: str) -> str:
        """Convert URL to defanged format for safe display."""
        return url.replace("http", "hxxp").replace(".", "[.]")

    def _make_request(self, url: str, method: str = 'GET', timeout: int = DEFAULT_REQUEST_TIMEOUT, **kwargs) -> requests.Response:
        """Make HTTP request with proper headers and error handling."""
        headers = kwargs.pop('headers', {})
        headers.setdefault('User-Agent', self.get_user_agent())
        time.sleep(RATE_LIMIT_DELAY)
        try:
            response = requests.request(method, url, headers=headers, timeout=timeout, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            raise APIError(f"Request failed for {url}: {str(e)}")
    
    def get_url_redirections(self, verbosity: bool = False) -> None:
        """Analyze URL redirections by following them and resolve the final IP address."""
        self.servers = []
        try:
            response = self._make_request(self.url, method='GET', allow_redirects=True)
            
            for resp in response.history:
                server_info = self._extract_server_info_from_response(resp)
                if server_info:
                    self.servers.append(server_info)
            
            final_server_info = self._extract_server_info_from_response(response, is_final=True)
            if final_server_info:
                self.servers.append(final_server_info)

            self._display_redirection_info(verbosity)

        except APIError as e:
            self.logger.error(f"Error analyzing URL redirections: {e}")
            printc("[red3][-][/red3] Failed to analyze URL redirections: Could not connect to the server.")
        except socket.gaierror as e:
            self.logger.error(f"DNS resolution failed for final host: {e}")
            printc(f"[red3][-][/red3] Failed to resolve IP for the final destination.")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during redirection analysis: {e}")
            printc(f"[red3][-][/red3] An unexpected error during redirection analysis: {str(e)}")

    def _extract_server_info_from_response(self, response: requests.Response, is_final: bool = False) -> Dict[str, str]:
        """Extracts server information from a requests.Response object."""
        server_dict = {}
        server_dict['Host'] = response.url
        server_dict['Status code'] = str(response.status_code)

        try:
            domain = self._get_domain_name(response.url)
            ip_address = socket.gethostbyname(domain) if domain else 'N/A'
            server_dict['IP address'] = ip_address
        except socket.gaierror:
            server_dict['IP address'] = 'N/A'
        
        server_dict['Country by IP'] = 'N/A'

        if is_final:
            self.expanded_url = response.url
            self.target_ip_address = server_dict['IP address']
        
        return server_dict
    
    def _display_redirection_info(self, verbosity: bool) -> None:
        """Display redirection information in formatted tables."""
        if not self.servers:
            printc('[red3][-][/red3] No redirection information could be retrieved.')
            return

        number_of_redirections = len(self.servers)
        if number_of_redirections > 1:
            printc(f"[gold1][!][/gold1] Found {number_of_redirections - 1} redirection(s)!")
            if verbosity:
                self._display_detailed_redirections()
            else:
                self._display_simple_redirections()
        else:
            printc('[spring_green2][+][/spring_green2] No redirection found!')
    
    def _display_detailed_redirections(self) -> None:
        """Display detailed redirection information in a table."""
        table = Table(title="Redirection Path Details", show_lines=True)
        table.add_column("Step", justify="center")
        table.add_column("URL", justify="left", max_width=60)
        table.add_column("Status", justify="center")
        table.add_column("IP Address", justify="center")
        
        for i, server in enumerate(self.servers):
            table.add_row(
                str(i + 1),
                server.get('Host', 'N/A'),
                server.get('Status code', 'N/A'),
                server.get('IP address', 'N/A')
            )
        printc(table)
    
    def _display_simple_redirections(self) -> None:
        """Display simple redirection information."""
        if not self.servers or len(self.servers) < 2: return
        
        table = Table(title="Redirection Summary", show_lines=True)
        table.add_column("Source URL", justify="left", max_width=50)
        table.add_column("Destination URL", justify="left", max_width=50)
        
        table.add_row(
            self.url,
            self.expanded_url
        )
        printc(table)
    
    def check_tracking_domain_name(self) -> None:
        """Check if the domain is a known IP tracking domain."""
        try:
            target_domain = self._get_domain_name(self.url)
            tracking_domains_file = self.db_path / "ip_tracking_domains.json"
            
            with open(tracking_domains_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for provider, domains in data.items():
                if target_domain in (domains if isinstance(domains, list) else [domains]):
                    printc(f"[gold1][!][/gold1] [gold1]{target_domain}[/gold1] is a known IP tracking domain from [bold]{provider}[/bold]!")
                    return
            
            printc("[spring_green2][+][/spring_green2] Domain not found in IP tracking database.")
            
        except (IOError, json.JSONDecodeError) as e:
            self.logger.error(f"Error checking tracking domains: {e}")
            printc("[red3][-][/red3] Error reading IP tracking domains database.")

    def check_url_shortener_domain(self) -> None:
        """Check if the domain is a known URL shortener."""
        try:
            target_domain = self._get_domain_name(self.url)
            shortener_domains_file = self.db_path / "url_shortener_domains.db"
            
            with open(shortener_domains_file, 'r', encoding='utf-8') as f:
                shortener_domains = {line.strip() for line in f}
            
            if target_domain in shortener_domains:
                printc(f"[gold1][!][/gold1] [gold1]{target_domain}[/gold1] is a known URL shortener.")
                printc(f"[gold1][!][/gold1] The original URL may be obfuscated.")
            else:
                printc("[spring_green2][+][/spring_green2] Domain not found in URL shortener database.")
                
        except IOError as e:
            self.logger.error(f"Error checking URL shortener domains: {e}")
            printc("[red3][-][/red3] Error reading URL shortener domains database.")

    def check_virustotal(self, target_url: str, api_key: str, verbosity: bool = False) -> None:
        """Check URL against VirusTotal database."""
        if not api_key:
            printc("[red3][-][/red3] Invalid or missing VirusTotal API key.")
            return
        
        try:
            url = "https://www.virustotal.com/api/v3/urls"
            payload = f"url={target_url}"
            headers = {"accept": "application/json", "x-apikey": api_key, "content-type": "application/x-www-form-urlencoded"}
            
            response = self._make_request(url, method='POST', data=payload, headers=headers)
            self._process_virustotal_response(response.json(), headers, verbosity)
                
        except APIError as e:
            self.logger.error(f"VirusTotal API error: {e}")
            printc(f"[red3][-][/red3] VirusTotal API error: {e}")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during VirusTotal check: {e}")
            printc(f"[red3][-][/red3] An unexpected error occurred during VirusTotal check.")

    def _process_virustotal_response(self, response_data: Dict[str, Any], headers: Dict[str, str], verbosity: bool) -> None:
        """Process VirusTotal API response and display results."""
        try:
            url_scan_link = response_data['data']['links']['self']
            max_wait_time = DEFAULT_MAX_API_WAIT
            wait_time = DEFAULT_API_WAIT_TIME
            elapsed_time = 0
            
            printc("[yellow][...][/yellow] Waiting for VirusTotal analysis to complete...")
            while elapsed_time < max_wait_time:
                analysis_response = self._make_request(url_scan_link, headers=headers)
                analysis_data = analysis_response.json()
                
                if analysis_data.get('data', {}).get('attributes', {}).get('stats'):
                    self._display_virustotal_results(analysis_data, verbosity)
                    return
                
                time.sleep(wait_time)
                elapsed_time += wait_time
            
            printc("[red3][-][/red3] VirusTotal scan timed out.")
                
        except APIError as e:
            self.logger.warning(f"Polling VirusTotal failed, retrying... Error: {e}")
            time.sleep(5) # Wait before next attempt
        except (KeyError, Exception) as e:
            self.logger.error(f"Error processing VirusTotal response: {e}")
            printc("[red3][-][/red3] Error processing VirusTotal results.")
            
    def _display_virustotal_results(self, analysis_data: Dict[str, Any], verbosity: bool) -> None:
        """Display VirusTotal analysis results."""
        try:
            attributes = analysis_data['data']['attributes']
            stats = attributes['stats']
            results = attributes['results']
            
            malicious_count = stats.get('malicious', 0)
            
            if malicious_count > 0:
                printc(f"[gold1][!][/gold1] [red3]{malicious_count} security vendor(s) flagged this URL as malicious[/red3].")
            else:
                printc("[spring_green2][+][/spring_green2] No security vendors flagged this URL as malicious.")
            
            printc(f"[bold]Security vendors' analysis summary:[/bold]")
            for stat, value in stats.items():
                printc(f"  - {stat.capitalize()}: {value}")
            
            if verbosity and malicious_count > 0:
                self._display_virustotal_details(results)
            
            url_info_id = analysis_data['meta']['url_info']['id']
            report_url = f"https://www.virustotal.com/gui/url/{url_info_id}"
            printc(f"[spring_green2][+][/spring_green2] For more information, see the full report: {report_url}")
            
        except (KeyError, Exception) as e:
            self.logger.error(f"Error displaying VirusTotal results: {e}")
            printc("[red3][-][/red3] Error displaying VirusTotal results.")

    def _display_virustotal_details(self, results: Dict[str, Any]) -> None:
        """Display detailed VirusTotal results in a table."""
        table = Table(title="Malicious Detections Details", show_lines=True)
        table.add_column("Vendor", style="cyan")
        table.add_column("Result", style="red")
        
        for vendor, result in results.items():
            if result.get('category') == "malicious":
                table.add_row(vendor, result.get('result', 'N/A'))
        
        if table.row_count > 0:
            printc(table)

    def check_urlscan_io(self, target_url: str, api_key: str, verbosity: bool = False) -> None:
        """Check URL using URLScan.io service."""
        if not api_key:
            printc("[red3][-][/red3] Invalid or missing URLScan.io API key.")
            return
        
        try:
            headers = {'API-Key': api_key, 'Content-Type': 'application/json'}
            data = {"url": target_url, "visibility": "unlisted"}
            
            response = self._make_request('https://urlscan.io/api/v1/scan/', method='POST', headers=headers, data=json.dumps(data))
            
            if response.status_code == 200:
                self._process_urlscan_response(response.json(), verbosity)
            elif response.status_code == 429:
                printc("[red3][!][/red3] URLScan.io rate-limit exceeded. Please try again later.")
            else:
                printc(f"[red3][-][/red3] URLScan.io API error: HTTP {response.status_code} - {response.text}")
                
        except APIError as e:
            printc(f"[red3][-][/red3] URLScan.io API error: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error checking URLScan.io: {e}")
            printc("[red3][-][/red3] An unexpected error occurred during URLScan.io check.")

    def _process_urlscan_response(self, response_data: Dict[str, Any], verbosity: bool) -> None:
        """Process URLScan.io response and wait for results."""
        try:
            result_api_url = response_data['api']
            max_wait_time = DEFAULT_MAX_API_WAIT
            wait_time = DEFAULT_API_WAIT_TIME
            elapsed_time = 0
            
            printc("[yellow][...][/yellow] Waiting for URLScan.io analysis to complete...")
            while elapsed_time < max_wait_time:
                try:
                    result_response = self._make_request(result_api_url)
                    if result_response.status_code == 200:
                        result_data = result_response.json()
                        if 'verdicts' in result_data:
                            self._display_urlscan_results(result_data, verbosity)
                            return
                except APIError as e:
                    # It's normal to get 404 while waiting for the scan to finish
                    if '404' not in str(e):
                        self.logger.warning(f"Polling URLScan.io failed: {e}")

                time.sleep(wait_time)
                elapsed_time += wait_time
            
            printc("[red3][-][/red3] URLScan.io scan timed out.")
                
        except (KeyError, Exception) as e:
            self.logger.error(f"Error processing URLScan.io response: {e}")
            printc("[red3][-][/red3] Error processing URLScan.io results.")

    def _display_urlscan_details(self, verdict_urlscan: Dict[str, Any]) -> None:
        """Display detailed URLScan.io verdict information."""
        printc(f"\n[bold]URLScan Verdict Details:[/bold]")
        for prop, value in verdict_urlscan.items():
            if value:
                printc(f"  - {prop.capitalize()}: {value}")

    def check_abuse_ip_db(self, ip_address: str, api_key: str, verbosity: bool = False) -> None:
        """Check IP address against AbuseIPDB."""
        if not api_key:
            printc("[red3][-][/red3] Invalid or missing AbuseIPDB API key.")
            return
        if not ip_address or ip_address == 'N/A':
            printc("[yellow][-][/yellow] Cannot check AbuseIPDB without a valid IP address.")
            return
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            params = {'ipAddress': ip_address, 'maxAgeInDays': '365'}
            headers = {'Accept': 'application/json', 'Key': api_key}
            
            response = self._make_request(url, params=params, headers=headers)
            self._display_abuseipdb_results(response.json(), verbosity)
                
        except APIError as e:
            printc(f"[red3][-][/red3] AbuseIPDB API error: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error checking AbuseIPDB: {e}")
            printc("[red3][-][/red3] An unexpected error occurred during AbuseIPDB check.")

    def _display_abuseipdb_results(self, response_data: Dict[str, Any], verbosity: bool) -> None:
        """Display AbuseIPDB results."""
        try:
            ip_info = response_data.get('data', {})
            if not ip_info:
                printc(f"[red3][-][/red3] No data returned from AbuseIPDB. {response_data.get('errors', '')}")
                return

            total_reports = ip_info.get('totalReports', 0)
            
            if total_reports > 0:
                printc(f"[gold1][!][/gold1] IP address [bold]{ip_info['ipAddress']}[/bold] was found in AbuseIPDB.")
                printc(f"  - Abuse Confidence Score: [bold red]{ip_info['abuseConfidenceScore']}%[/bold red]")
                printc(f"  - Total Reports: {total_reports}")
                printc(f"  - Last Reported At: {ip_info.get('lastReportedAt', 'N/A')}")

                if verbosity:
                    self._display_abuseipdb_details(ip_info)
                else:
                    self._display_abuseipdb_summary(ip_info)
            else:
                printc("[spring_green2][+][/spring_green2] IP address not found in AbuseIPDB or has a clean record.")
                
        except (KeyError, Exception) as e:
            self.logger.error(f"Error displaying AbuseIPDB results: {e}")
            printc("[red3][-][/red3] Error displaying AbuseIPDB results.")
    
    def _display_abuseipdb_details(self, ip_info: Dict[str, Any]) -> None:
        """Display detailed AbuseIPDB information."""
        printc("[bold]AbuseIPDB Details:[/bold]")
        for prop, value in ip_info.items():
            if value is not None:
                printc(f"  - {prop}: {value}")
    
    def _display_abuseipdb_summary(self, ip_info: Dict[str, Any]) -> None:
        """Display summary AbuseIPDB information."""
        printc(f"  - ISP: {ip_info.get('isp', 'N/A')}")
        printc(f"  - Usage Type: {ip_info.get('usageType', 'N/A')}")
        printc(f"  - Is Tor Node: {'Yes' if ip_info.get('isTor') else 'No'}")

    def _format_whois_value(self, value: Any) -> str:
        """Helper to format WHOIS values for display."""
        if isinstance(value, list):
            if value and isinstance(value[0], datetime):
                return ', '.join(d.strftime('%Y-%m-%d %H:%M:%S') for d in value)
            return ', '.join(map(str, value))
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%d %H:%M:%S')
        return str(value) if value is not None else "N/A"

    def get_whois_info(self, target: str, verbosity: bool = False) -> None:
        """Perform WHOIS lookup on a domain or IP address."""
        if not target or target in ['N/A', '0.0.0.0']:
            printc("[yellow][-][/yellow] Cannot perform WHOIS lookup without a valid domain or IP.")
            return

        try:
            whois_info = whois.whois(target)
            if not whois_info or not whois_info.domain_name:
                printc(f"[red3][-][/red3] No WHOIS information could be retrieved for {target}.")
                return
            
            printc(f"[bold]WHOIS Information for {whois_info.get('domain_name', target)}:[/bold]")
            if verbosity:
                self._display_detailed_whois(whois_info)
            else:
                self._display_summary_whois(whois_info)
                
        except PywhoisError as e:
            self.logger.error(f"WHOIS lookup failed for {target}: {e}")
            printc(f"[red3][-][/red3] WHOIS lookup failed. It may be a private or invalid domain/IP.")
        except Exception as e:
            self.logger.error(f"Unexpected error in WHOIS lookup for {target}: {e}")
            printc(f"[red3][-][/red3] An unexpected error occurred during WHOIS lookup.")
    
    def _display_detailed_whois(self, whois_info: whois.WhoisEntry) -> None:
        """Display detailed WHOIS information."""
        for key, value in whois_info.items():
            value_str = self._format_whois_value(value)
            if value_str != "N/A":
                printc(f"  - {key.replace('_', ' ').capitalize()}: {value_str}")
    
    def _display_summary_whois(self, whois_info: whois.WhoisEntry) -> None:
        """Display summary WHOIS information."""
        summary_keys = ['registrar', 'creation_date', 'expiration_date', 'emails', 'country']
        for key in summary_keys:
            if key in whois_info:
                value = whois_info[key]
                value_str = self._format_whois_value(value)
                if value_str != "N/A":
                    printc(f"  - {key.replace('_', ' ').capitalize()}: {value_str}")
    
    def capture_and_display_screenshot(self, auto_display: bool = False) -> None:
        """Capture and optionally display a webpage screenshot."""
        screenshot_url = self.target_webpage_screenshot or f"https://api.pagepeeker.com/v2/thumbs.php?size=x&url={self.expanded_url or self.url}"
        
        try:
            if auto_display or self._should_display_screenshot():
                printc("[yellow][...][/yellow] Fetching screenshot...")
                response = self._make_request(screenshot_url, stream=True)
                self._display_screenshot(response)
            else:
                printc("[spring_green2][+][/spring_green2] Screenshot capture was skipped by user.")
                
        except APIError as e:
            self.logger.error(f"Error fetching screenshot: {e}")
            printc(f"[red3][-][/red3] Screenshot unavailable: Failed to fetch the image.")
        except Exception as e:
            self.logger.error(f"Error capturing screenshot: {e}")
            printc(f"[red3][-][/red3] Screenshot unavailable: {str(e)}")
    
    def _should_display_screenshot(self) -> bool:
        """Ask user if they want to see the screenshot."""
        try:
            user_choice = input(f"Would you like to view a screenshot of the target page? [Y/n]: ")
            return user_choice.lower() in ['', 'y', 'yes']
        except (EOFError, KeyboardInterrupt):
            printc("\nSkipping screenshot display.")
            return False
    
    def _display_screenshot(self, response: requests.Response) -> None:
        """Display the screenshot using PIL."""
        try:
            with Image.open(BytesIO(response.content)) as img:
                img.show()
                printc("[spring_green2][+][/spring_green2] Screenshot displayed in default image viewer.")
        except Exception as e:
            self.logger.error(f"Error displaying screenshot: {e}")
            printc(f"[red3][-][/red3] Failed to open screenshot image. It may be corrupted or in an unsupported format.")
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get a summary of the analysis results."""
        return {
            'url': self.url,
            'defanged_url': self.defanged_url,
            'final_url': self.expanded_url,
            'final_ip': self.target_ip_address,
            'redirections_count': len(self.servers) -1 if self.servers else 0,
            'screenshot_available': bool(self.target_webpage_screenshot),
            'domain': self._get_domain_name(self.url)
        }
