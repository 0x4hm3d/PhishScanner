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
from unittest.mock import patch, MagicMock, mock_open

# Add the parent directory to the path to allow importing the scripts
sys.path.insert(0, str(Path(__file__).resolve().parent))

from phish_detector import PhishDetector, InvalidURLError, FileNotFoundError as PhishDetectorFileNotFoundError
import PhishScanner

# --- Test Data and Mocks ---

# A mock for a successful requests.Response object
class MockResponse:
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
        self.test_dir.mkdir()
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

    def test_init_missing_db_file(self):
        """Tests that initialization fails if a database file is missing."""
        (self.test_dir / "user_agents.db").unlink() # Remove a required file
        with self.assertRaises(PhishDetectorFileNotFoundError):
            PhishDetector(self.valid_url, db_path=self.test_dir)

    def test_check_url_shortener(self):
        """Tests the URL shortener check logic."""
        detector = PhishDetector("https://bit.ly/xyz", db_path=self.test_dir)
        self.assertTrue(detector.check_url_shortener_domain())

    def test_check_tracking_domain(self):
        """Tests the tracking domain check logic."""
        detector = PhishDetector("http://track.me/resource", db_path=self.test_dir)
        # In the revised script, these checks print output instead of returning.
        # We can capture stdout to verify.
        captured_output = io.StringIO()
        sys.stdout = captured_output
        detector.check_tracking_domain_name()
        sys.stdout = sys.__stdout__
        self.assertIn("is a known IP tracking domain", captured_output.getvalue())

    @patch('phish_detector.PhishDetector._make_request')
    @patch('phish_detector.socket.gethostbyname', return_value="93.184.216.34")
    def test_redirection_logic(self, mock_gethostbyname, mock_make_request):
        """Tests the internal redirection logic using mocks."""
        # Simulate a redirection from http to https
        mock_history_response = MockResponse({}, 301, text="redirect")
        mock_history_response.url = "http://example.com"
        mock_final_response = MockResponse({}, 200, text="final page", history=[mock_history_response])
        mock_final_response.url = "https://example.com"
        mock_make_request.return_value = mock_final_response

        detector = PhishDetector(self.valid_url, db_path=self.test_dir)
        detector.get_url_redirections()
        
        self.assertEqual(detector.expanded_url, "https://example.com")
        self.assertEqual(detector.target_ip_address, "93.184.216.34")
        self.assertEqual(len(detector.servers), 2) # History (1) + Final (1)

    @patch('phish_detector.PhishDetector._make_request')
    def test_virustotal_malicious(self, mock_make_request):
        """Tests VirusTotal check with a mocked malicious response."""
        # Mock the submission and then the polling response
        mock_submit_response = {"data": {"links": {"self": "http://fake-vt-api/123"}}}
        mock_analysis_response = {
            "data": {"attributes": {"stats": {"malicious": 1}, "results": {}}},
            "meta": {"url_info": {"id": "fake_id"}}
        }
        mock_make_request.side_effect = [
            MockResponse(mock_submit_response, 200),
            MockResponse(mock_analysis_response, 200)
        ]

        detector = PhishDetector(self.valid_url, db_path=self.test_dir)
        captured_output = io.StringIO()
        sys.stdout = captured_output
        detector.check_virustotal(self.valid_url, "fake_vt_key")
        sys.stdout = sys.__stdout__
        
        self.assertIn("flagged this URL as malicious", captured_output.getvalue())

class TestPhishScannerCLI(unittest.TestCase):
    """Tests the PhishScanner.py CLI application and argument parsing."""

    def test_arg_parser_required_url(self):
        """Tests that the -u/--url argument is required."""
        with self.assertRaises(SystemExit):
            PhishScanner.parse_arguments() # No args should fail

    def test_arg_parser_screenshot_flags(self):
        """Tests the mutually exclusive screenshot flags."""
        # Should work
        args = PhishScanner.parse_arguments(['-u', 'http://a.com', '--screenshot'])
        self.assertTrue(args.screenshot)
        self.assertFalse(args.no_screenshot)

        # Should also work
        args = PhishScanner.parse_arguments(['-u', 'http://a.com', '--no-screenshot'])
        self.assertFalse(args.screenshot)
        self.assertTrue(args.no_screenshot)
        
        # Should fail if both are provided
        with self.assertRaises(SystemExit):
            PhishScanner.parse_arguments(['-u', 'http://a.com', '--screenshot', '--no-screenshot'])

    @patch('PhishScanner.PhishDetector')
    @patch('PhishScanner.load_api_keys', return_value={})
    @patch('PhishScanner.display_completion_summary')
    @patch('PhishScanner.save_results_to_json')
    def test_main_flow_no_screenshot_flag(self, mock_save, mock_summary, mock_load_keys, MockPhishDetector):
        """Tests that --no-screenshot skips the screenshot call."""
        # Mock the detector instance to check calls
        mock_detector_instance = MagicMock()
        MockPhishDetector.return_value = mock_detector_instance

        # Simulate running `PhishScanner.py -u http://a.com --no-screenshot`
        with patch.object(sys, 'argv', ['PhishScanner.py', '-u', 'http://a.com', '--no-screenshot']):
            PhishScanner.main()
        
        # Verify that the screenshot function was NOT called
        mock_detector_instance.capture_and_display_screenshot.assert_not_called()

    @patch('PhishScanner.PhishDetector')
    @patch('PhishScanner.load_api_keys', return_value={})
    @patch('PhishScanner.display_completion_summary')
    @patch('PhishScanner.save_results_to_json')
    def test_main_flow_screenshot_flag(self, mock_save, mock_summary, mock_load_keys, MockPhishDetector):
        """Tests that --screenshot calls capture with auto_display=True."""
        mock_detector_instance = MagicMock()
        MockPhishDetector.return_value = mock_detector_instance

        # Simulate running `PhishScanner.py -u http://a.com --screenshot`
        with patch.object(sys, 'argv', ['PhishScanner.py', '-u', 'http://a.com', '--screenshot']):
            PhishScanner.main()
        
        # Verify that the screenshot function WAS called with auto_display=True
        mock_detector_instance.capture_and_display_screenshot.assert_called_once_with(auto_display=True)

    @patch('PhishScanner.PhishDetector')
    @patch('PhishScanner.load_api_keys', return_value={})
    @patch('PhishScanner.display_completion_summary')
    @patch('PhishScanner.save_results_to_json')
    def test_main_flow_default_screenshot(self, mock_save, mock_summary, mock_load_keys, MockPhishDetector):
        """Tests that the default behavior calls capture with auto_display=False."""
        mock_detector_instance = MagicMock()
        MockPhishDetector.return_value = mock_detector_instance

        # Simulate running `PhishScanner.py -u http://a.com`
        with patch.object(sys, 'argv', ['PhishScanner.py', '-u', 'http://a.com']):
            PhishScanner.main()
        
        # Verify that the screenshot function WAS called with auto_display=False (for interactive prompt)
        mock_detector_instance.capture_and_display_screenshot.assert_called_once_with(auto_display=False)

if __name__ == '__main__':
    unittest.main(verbosity=2)
