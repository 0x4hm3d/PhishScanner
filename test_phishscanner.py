#!/usr/bin/env python3
"""
Unit tests for the PhishScanner tool.

This script tests both the core logic in 'phish_detector.py' and the CLI
application flow in 'PhishScanner.py'. It uses mocking to prevent
actual network requests.
"""
import unittest
import sys
import io
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock
from typing import List, Optional

# Add the parent directory to the path to allow importing the scripts
sys.path.insert(0, str(Path(__file__).resolve().parent))

from phish_detector import PhishDetector, InvalidURLError, FileNotFoundError as PhishDetectorFileNotFoundError
import PhishScanner
import requests

class MockResponse:
    """A mock for a successful requests.Response object."""
    def __init__(self, json_data, status_code, text="", history=None):
        self.json_data = json_data
        self.status_code = status_code
        self.text = text
        self.history = history or []

    def json(self):
        return self.json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP Error {self.status_code}")

    @property
    def content(self):
        return self.text.encode('utf-8')

class TestPhishDetector(unittest.TestCase):
    """Tests the core PhishDetector class logic."""

    def setUp(self):
        """Set up a temporary database directory for testing."""
        self.test_dir = Path("test_temp_db")
        self.test_dir.mkdir(exist_ok=True)
        (self.test_dir / "user_agents.db").write_text("TestAgent/1.0\n")
        (self.test_dir / "url_shortener_domains.db").write_text("bit.ly\n")
        (self.test_dir / "ip_tracking_domains.json").write_text('{"TestTracker": ["track.me"]}')
        self.valid_url = "http://example.com"

    def tearDown(self):
        """Remove the temporary directory after tests."""
        shutil.rmtree(self.test_dir)

    def test_init_valid_url(self):
        """Tests successful initialization with a valid URL."""
        try:
            detector = PhishDetector(self.valid_url, db_path=self.test_dir)
            self.assertEqual(detector.url, self.valid_url)
        except Exception as e:
            self.fail(f"PhishDetector initialization failed unexpectedly: {e}")

    def test_init_invalid_url(self):
        """Tests that initialization fails with an invalid URL."""
        with self.assertRaises(InvalidURLError):
            PhishDetector("not-a-url", db_path=self.test_dir)

    def test_check_url_shortener_true(self):
        """Tests the URL shortener check returns True for a known shortener."""
        detector = PhishDetector("https://bit.ly/xyz", db_path=self.test_dir)
        self.assertTrue(detector.check_url_shortener_domain())

    def test_check_url_shortener_false(self):
        """Tests the URL shortener check returns False for a normal domain."""
        detector = PhishDetector("https://example.com", db_path=self.test_dir)
        self.assertFalse(detector.check_url_shortener_domain())

    def test_check_tracking_domain_true(self):
        """Tests the tracking domain check returns True for a known tracker."""
        detector = PhishDetector("http://track.me/resource", db_path=self.test_dir)
        self.assertTrue(detector.check_tracking_domain_name())
        self.assertEqual(detector.tracking_provider, "TestTracker")

    def test_check_tracking_domain_false(self):
        """Tests the tracking domain check returns False for a normal domain."""
        detector = PhishDetector("https://example.com", db_path=self.test_dir)
        self.assertFalse(detector.check_tracking_domain_name())

    @patch('phish_detector.PhishDetector._make_request')
    @patch('phish_detector.socket.gethostbyname', return_value="93.184.216.34")
    def test_redirection_logic(self, mock_gethostbyname, mock_make_request):
        """Tests the internal redirection logic using mocks."""
        mock_history_response = MockResponse({}, 301, text="redirect")
        mock_history_response.url = "http://example.com"
        mock_final_response = MockResponse({}, 200, text="final page", history=[mock_history_response])
        mock_final_response.url = "https://example.com"
        mock_make_request.return_value = mock_final_response

        detector = PhishDetector(self.valid_url, db_path=self.test_dir)
        detector.get_url_redirections()
        
        self.assertEqual(detector.expanded_url, "https://example.com")
        self.assertEqual(detector.target_ip_address, "93.184.216.34")

class TestPhishScannerCLI(unittest.TestCase):
    """Tests the PhishScanner.py CLI application and argument parsing."""

    def _setup_mock_detector(self):
        """Helper to create a well-defined mock PhishDetector instance."""
        mock_detector = MagicMock(spec=PhishDetector)
        mock_detector.url = 'http://a.com'
        mock_detector.defanged_url = 'hxxp[://]a[.]com'
        mock_detector.expanded_url = 'http://a.com'
        mock_detector.target_ip_address = '1.2.3.4'
        mock_detector.check_url_shortener_domain.return_value = False
        mock_detector.check_tracking_domain_name.return_value = False
        mock_detector._get_domain_name.return_value = 'a.com'
        mock_detector.get_analysis_summary.return_value = {} # Add a default summary
        return mock_detector

    def test_arg_parser_screenshot_flags(self):
        """Tests the mutually exclusive screenshot flags."""
        args = PhishScanner.parse_arguments(['-u', 'http://a.com', '--screenshot'])
        self.assertTrue(args.screenshot)
        self.assertFalse(args.no_screenshot)

        args = PhishScanner.parse_arguments(['-u', 'http://a.com', '--no-screenshot'])
        self.assertFalse(args.screenshot)
        self.assertTrue(args.no_screenshot)
        
        with self.assertRaises(SystemExit):
            with patch('sys.stderr', new_callable=io.StringIO): # Suppress argparse error output
                PhishScanner.parse_arguments(['-u', 'http://a.com', '--screenshot', '--no-screenshot'])

    @patch('PhishScanner.PhishDetector')
    @patch('PhishScanner.load_api_keys', return_value={'abuse_ip_db': '', 'urlscan_io': '', 'virustotal': ''})
    @patch('PhishScanner.display_completion_summary')
    def test_main_flow_no_screenshot_flag(self, mock_summary, mock_load_keys, MockPhishDetector):
        """Tests that --no-screenshot skips the screenshot call."""
        mock_detector_instance = self._setup_mock_detector()
        MockPhishDetector.return_value = mock_detector_instance

        with patch.object(sys, 'argv', ['PhishScanner.py', '-u', 'http://a.com', '--no-screenshot']):
            PhishScanner.main()
        
        mock_detector_instance.capture_and_display_screenshot.assert_not_called()

    @patch('PhishScanner.PhishDetector')
    @patch('PhishScanner.load_api_keys', return_value={'abuse_ip_db': '', 'urlscan_io': '', 'virustotal': ''})
    @patch('PhishScanner.display_completion_summary')
    def test_main_flow_screenshot_flag(self, mock_summary, mock_load_keys, MockPhishDetector):
        """Tests that --screenshot calls capture with auto_display=True."""
        mock_detector_instance = self._setup_mock_detector()
        MockPhishDetector.return_value = mock_detector_instance

        with patch.object(sys, 'argv', ['PhishScanner.py', '-u', 'http://a.com', '--screenshot']):
            PhishScanner.main()
        
        mock_detector_instance.capture_and_display_screenshot.assert_called_once_with(auto_display=True)

    @patch('PhishScanner.PhishDetector')
    @patch('PhishScanner.load_api_keys', return_value={'abuse_ip_db': '', 'urlscan_io': '', 'virustotal': ''})
    @patch('PhishScanner.display_completion_summary')
    def test_main_flow_default_screenshot_behavior(self, mock_summary, mock_load_keys, MockPhishDetector):
        """Tests that default behavior calls capture with auto_display=False for interactive prompt."""
        mock_detector_instance = self._setup_mock_detector()
        MockPhishDetector.return_value = mock_detector_instance

        with patch.object(sys, 'argv', ['PhishScanner.py', '-u', 'http://a.com']):
            PhishScanner.main()
        
        mock_detector_instance.capture_and_display_screenshot.assert_called_once_with(auto_display=False)

if __name__ == '__main__':
    unittest.main(verbosity=2)
