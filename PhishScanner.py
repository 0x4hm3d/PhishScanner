#!/usr/bin/env python3
"""
PhishScanner - A comprehensive phishing website detection tool.

This module provides functionality to analyze URLs for potential phishing threats
using multiple detection methods including VirusTotal, URLScan.io, and
various domain analysis techniques.

Author: 0x4hm3d
Version: 2.2 (Revised)
"""

import argparse
import configparser
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple, Any, Set
import json

# The phish_detector.py file provided in the previous turn is compatible and does not require changes.
from phish_detector import PhishDetector, InvalidURLError
from rich import print as printc
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.table import Table

# Constants
VERSION = "2.2"
AUTHOR = "0x4hm3d"
DEFAULT_CONFIG_PATH = Path("config/config.ini")
BANNER_WIDTH = 80
API_KEY_PLACEHOLDERS: Set[str] = {
    'your_abuseipdb_api_key',
    'your_urlscan_api_key',
    'your_virustotal_api_key',
    'ABUSE_APT_KEY',
    'VT_API_KEY',
    'URLSCAN_API_KEY',
    ''
}

console = Console()

class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing."""
    pass

def setup_logging(verbose: bool = False, log_file: Optional[Path] = None) -> None:
    """Configure logging with rich formatting and optional file output."""
    level = logging.DEBUG if verbose else logging.INFO
    handlers = [RichHandler(console=console, rich_tracebacks=True, show_path=verbose)]
    
    if log_file:
        try:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            handlers.append(file_handler)
        except OSError as e:
            printc(f"[red3][-][/red3] Could not create log file at {log_file}: {e}")

    logging.basicConfig(level=level, format="%(message)s", datefmt="[%X]", handlers=handlers)

def display_banner() -> None:
    """Display the application banner."""
    banner_text = f"""
[bold cyan]╔═╗┬ ┬┬┌─┐┬ ┬╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐[/bold cyan]
[bold cyan]╠═╝├─┤│└─┐├─┤╚═╗│  ├─┤││││││├┤ ├┬┘[/bold cyan]
[bold cyan]╩  ┴ ┴┴└─┘┴ ┴╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─[/bold cyan]

[bold white]Version: {VERSION} | Author: {AUTHOR}[/bold white]
[dim]{'─' * 40}[/dim]
[bold green]🎣 Advanced Phishing Detection Tool[/bold green]
[bold yellow]🔍 First Check, Then Click![/bold yellow]
"""
    panel = Panel(banner_text, title="[bold red]PhishScanner[/bold red]", border_style="cyan", padding=(1, 2))
    console.print(panel)

def parse_arguments() -> argparse.Namespace:
    """Parse and validate command line arguments."""
    parser = argparse.ArgumentParser(
        prog='PhishScanner.py',
        description='A comprehensive Python tool for detecting phishing websites.',
        epilog='Contact X: @iahmedelhabashy'
    )
    parser.add_argument('-u', '--url', metavar="URL", help='Suspected URL to analyze', required=True)
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output for detailed analysis')
    parser.add_argument('-f', '--config', metavar="PATH", type=Path, default=DEFAULT_CONFIG_PATH, help='Path to config.ini file')
    parser.add_argument('--log-file', metavar="PATH", type=Path, help='Path to log file for detailed logging')
    parser.add_argument('--output-file', type=Path, help='Save JSON results to the specified file path')

    # Create a mutually exclusive group for screenshot behavior to avoid conflicts
    screenshot_group = parser.add_mutually_exclusive_group()
    screenshot_group.add_argument(
        '--screenshot',
        action='store_true',
        help='Automatically capture screenshot without interactive prompting.'
    )
    screenshot_group.add_argument(
        '--no-screenshot',
        action='store_true',
        help='Disable the screenshot capture feature entirely.'
    )
    
    return parser.parse_args()

def load_api_keys(config_path: Path) -> Dict[str, str]:
    """Load and validate API configuration from file."""
    default_keys = {'abuse_ip_db': '', 'urlscan_io': '', 'virustotal': ''}
    if not config_path.exists():
        logging.warning(f"Configuration file not found at {config_path}. API-based checks will be skipped.")
        return default_keys
    
    try:
        config = configparser.ConfigParser()
        config.read(config_path)
        if 'APIs' not in config:
            raise ConfigurationError("Missing [APIs] section in configuration file.")
            
        api_keys = {
            'abuse_ip_db': config['APIs'].get('ABUSEIPDB_API_KEY', ''),
            'urlscan_io': config['APIs'].get('URLSCAN_API_KEY', ''),
            'virustotal': config['APIs'].get('VIRUSTOTAL_API_KEY', '')
        }
        
        for service, key in api_keys.items():
            if key in API_KEY_PLACEHOLDERS and key != '':
                logging.warning(f"{service} API key appears to be a placeholder.")
        return api_keys
        
    except (configparser.Error, ConfigurationError) as e:
        logging.error(f"Error loading configuration: {e}")
        return default_keys

def is_api_available(service_name: str, api_key: str) -> bool:
    """Check if an API key is configured and available for use."""
    if api_key in API_KEY_PLACEHOLDERS:
        printc(f"[yellow][!][/yellow] {service_name} check skipped: API key not configured.")
        return False
    return True

def run_phishing_analysis(detector: PhishDetector, api_keys: Dict[str, str], args: argparse.Namespace) -> Dict[str, Any]:
    """Execute the complete phishing analysis workflow."""
    results = {'url': detector.url, 'timestamp': datetime.now().isoformat(), 'checks': {}}
    
    def run_check(description: str, check_function, *f_args, **f_kwargs):
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as progress:
            task = progress.add_task(description, total=None)
            try:
                check_function(*f_args, **f_kwargs)
                return {'status': 'completed'}
            except Exception as e:
                logging.error(f"Error during '{description}': {e}", exc_info=args.verbose)
                return {'status': 'failed', 'error': str(e)}
            finally:
                progress.remove_task(task)

    printc(Panel(f"[bold]Target URL:[/] [cyan]{detector.defanged_url}[/]", title="[bold]Analysis Start[/]", border_style="blue"))

    checks_to_run = [
        ("Analyzing URL redirections...", detector.get_url_redirections, 'redirections', {'verbosity': args.verbose}),
        ("Checking IP tracking domains...", detector.check_tracking_domain_name, 'ip_tracking', {}),
        ("Checking URL shortener domains...", detector.check_url_shortener_domain, 'url_shortener', {}),
    ]

    for desc, func, key, kwargs in checks_to_run:
        results['checks'][key] = run_check(desc, func, **kwargs)

    final_url = detector.expanded_url or detector.url
    final_ip = detector.target_ip_address
    final_domain = detector._get_domain_name(final_url)

    # API-based checks
    if is_api_available("VirusTotal", api_keys['virustotal']):
        printc("\n[bold]VirusTotal Report[/]")
        results['checks']['virustotal'] = run_check("Querying VirusTotal...", detector.check_virustotal, final_url, api_keys['virustotal'], args.verbose)
    
    if is_api_available("URLScan.io", api_keys['urlscan_io']):
        printc("\n[bold]URLScan.io Report[/]")
        results['checks']['urlscan'] = run_check("Querying URLScan.io...", detector.check_urlscan_io, final_url, api_keys['urlscan_io'], args.verbose)
    
    if is_api_available("AbuseIPDB", api_keys['abuse_ip_db']):
        printc("\n[bold]AbuseIPDB Report[/]")
        results['checks']['abuseipdb'] = run_check("Querying AbuseIPDB...", detector.check_abuse_ip_db, final_ip, api_keys['abuse_ip_db'], args.verbose)

    # WHOIS and Screenshot
    printc("\n[bold]WHOIS Lookup[/]")
    results['checks']['whois'] = run_check("Performing WHOIS lookup...", detector.get_whois_info, final_domain or final_ip, args.verbose)
    
    if not args.no_screenshot:
        printc("\n[bold]Webpage Screenshot[/]")
        # The 'auto_display' parameter is set to True if the '--screenshot' flag is used,
        # bypassing the interactive prompt. Otherwise, it remains False, triggering the prompt.
        results['checks']['screenshot'] = run_check(
            "Capturing screenshot...",
            detector.capture_and_display_screenshot,
            auto_display=args.screenshot
        )
    else:
        results['checks']['screenshot'] = {'status': 'skipped', 'reason': 'Disabled by --no-screenshot flag'}

    results['summary'] = detector.get_analysis_summary()
    return results

def save_results_to_json(results: Dict[str, Any], output_file: Path) -> None:
    """Save analysis results to a JSON file."""
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        printc(f"[spring_green2][+][/spring_green2] Results saved to: {output_file.resolve()}")
    except (IOError, OSError) as e:
        logging.error(f"Error saving results to {output_file}: {e}")
        printc(f"[red3][-][/red3] Failed to save results: {e}")

def display_completion_summary(results: Dict[str, Any]) -> None:
    """Display a summary table of the analysis performed."""
    table = Table(title="Analysis Completion Summary", show_header=True, header_style="bold magenta")
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    
    for check, result in results['checks'].items():
        status = result['status']
        if status == 'completed': status_display = "[green]✓ Completed[/green]"
        elif status == 'failed': status_display = "[red]✗ Failed[/red]"
        elif status == 'skipped': status_display = "[yellow]⚠ Skipped[/yellow]"
        else: status_display = f"[dim]{status}[/dim]"
        table.add_row(check.replace('_', ' ').title(), status_display)
    
    console.print(table)
    summary = results['summary']
    summary_text = f"[bold]Final URL:[/] [cyan]{summary.get('final_url', 'N/A')}[/]\n[bold]Final IP:[/][cyan] {summary.get('final_ip', 'N/A')}[/]"
    console.print(Panel(summary_text, title="[bold green]Scan Complete[/bold green]", border_style="green"))

def main() -> None:
    """Main application entry point."""
    try:
        args = parse_arguments()
        setup_logging(args.verbose, args.log_file)
        display_banner()
        
        api_keys = load_api_keys(args.config)
        detector = PhishDetector(args.url)
        
        results = run_phishing_analysis(detector, api_keys, args)
        
        if args.output_file:
            save_results_to_json(results, args.output_file)
        
        display_completion_summary(results)
        
    except InvalidURLError as e:
        logging.error(f"Invalid URL provided: {e}")
        printc(f"[red3][!][/red3] {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        logging.error(f"A required file was not found: {e}")
        printc(f"[red3][!][/red3] {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        printc("\n[yellow][!][/yellow] Analysis interrupted by user. Exiting.")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"An unexpected error occurred: {e}", exc_info=True)
        printc(f"[red3][!][/red3] An unexpected critical error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
