#!/usr/bin/env python3
"""
PhishDetector Module
Performs phishing URL analysis including redirection, domain checks, etc.

Author: 0x4hm3d
Version: 2.0
"""

import re
import json
import socket
import requests
from pathlib import Path
from urllib.parse import urlparse
from random import choice


# Custom Exceptions
class PhishDetectorError(Exception): pass
class InvalidURLError(PhishDetectorError): pass
class APIError(PhishDetectorError): pass


class PhishDetector:
    def __init__(self, url: str, db_path: Path):
        if not self._is_valid_url(url):
            raise InvalidURLError(f"Invalid URL: {url}")

        self.url = url
        self.db_path = db_path
        self.user_agents = self._load_user_agents()
        self.shortener_domains = self._load_db_file("url_shortener_domains.db")
        self.tracking_domains = self._load_tracking_domains()
        self.defanged_url = self._defang_url(url)
        self.expanded_url = None
        self.target_ip_address = self._resolve_ip()

    def _is_valid_url(self, url: str) -> bool:
        return re.match(r'^https?://[^\s/$.?#].[^\s]*$', url) is not None

    def _defang_url(self, url: str) -> str:
        return url.replace("http", "hxxp").replace(".", "[.]").replace("://", "[://]")

    def _resolve_ip(self) -> str:
        try:
            domain = self._get_domain_name(self.url)
            return socket.gethostbyname(domain)
        except Exception:
            return "0.0.0.0"

    def _get_domain_name(self, url: str) -> str:
        return urlparse(url).netloc

    def _load_user_agents(self):
        user_agents_file = self.db_path / "user_agents.db"
        if not user_agents_file.exists():
            raise PhishDetectorError("User agent database not found.")
        with open(user_agents_file) as f:
            return [line.strip() for line in f if line.strip()]

    def _load_db_file(self, filename):
        db_file = self.db_path / filename
        if not db_file.exists():
            raise PhishDetectorError(f"{filename} not found.")
        with open(db_file) as f:
            return [line.strip() for line in f if line.strip()]

    def _load_tracking_domains(self):
        file = self.db_path / "ip_tracking_domains.json"
        if not file.exists():
            raise PhishDetectorError("IP tracking domains DB not found.")
        with open(file) as f:
            return json.load(f)

    def get_user_agent(self) -> str:
        return choice(self.user_agents)

    def check_tracking_domain_name(self):
        domain = self._get_domain_name(self.url)
        for provider, domains in self.tracking_domains.items():
            if domain in domains:
                return True
        return False

    def check_url_shortener_domain(self):
        domain = self._get_domain_name(self.url)
        return domain in self.shortener_domains

    def get_analysis_summary(self):
        return {
            "url": self.url,
            "defanged_url": self.defanged_url,
            "expanded_url": self.expanded_url or self.url,
            "target_ip": self.target_ip_address,
            "domain": self._get_domain_name(self.url),
            "uses_shortener": self.check_url_shortener_domain(),
            "uses_tracking_domain": self.check_tracking_domain_name(),
        }

    def _make_request(self, url: str, method="GET", headers=None):
        try:
            response = requests.request(method, url, headers=headers, timeout=10)
            response.raise_for_status()
            return response
        except Exception as e:
            raise APIError(str(e))

    def get_url_redirections(self, verbose=False):
        """Analyze and follow URL redirections."""
        try:
            session = requests.Session()
            session.max_redirects = 10

            if verbose:
                print(f"[*] Starting redirection check for: {self.url}")

            response = session.get(self.url, allow_redirects=True, timeout=10)
            redirection_chain = [resp.url for resp in response.history] + [response.url]

            if verbose:
                print("[*] Redirection chain:")
                for url in redirection_chain:
                    print(f"  ↳ {url}")

            self.expanded_url = response.url
            return redirection_chain

        except requests.exceptions.TooManyRedirects:
            raise APIError("Too many redirects encountered during redirection analysis.")
        except requests.exceptions.RequestException as e:
            raise APIError(f"Request error during redirection analysis: {e}")
