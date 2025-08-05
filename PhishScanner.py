#!/usr/bin/env python3
"""
PhishScanner - A comprehensive phishing website detection tool.

This module provides functionality to analyze URLs for potential phishing threats
using multiple detection methods including Google Safe Browsing, VirusTotal,
URLScan.io, and various domain analysis techniques.

Author: 0x4hm3d
Version: 2.0
"""

import argparse
import configparser
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple, Any
import json

from phish_detector import PhishDetector, PhishDetectorError, InvalidURLError, APIError
from rich import print as printc
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.table import Table

# Constants
VERSION = "2.0"
AUTHOR = "0x4hm3d"
DEFAULT_CONFIG_PATH = Path("config/config.ini")
BANNER_WIDTH = 80

# Initialize rich console
console = Console()


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing."""
    pass


def setup_logging(verbose: bool = False, log_file: Optional[Path] = None) -> None:
    """
    Configure logging with rich formatting and optional file output.
    
    Args:
        verbose: Enable debug level logging
        log_file: Optional file path for log output
    """
    level = logging.DEBUG if verbose else logging.INFO
    handlers = [RichHandler(console=console, rich_tracebacks=True)]
    
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        handlers.append(file_handler)
    
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers
    )


def display_banner() -> None:
    """Display the application banner with improved formatting."""
    banner_text = f"""
[bold cyan]╔═╗┬ ┬┬┌─┐┬ ┬╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐[/bold cyan]
[bold cyan]╠═╝├─┤│└─┐├─┤╚═╗│  ├─┤││││││├┤ ├┬┘[/bold cyan]
[bold cyan]╩  ┴ ┴┴└─┘┴ ┴╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─[/bold cyan]

[bold white]Version: {VERSION} | Author: {AUTHOR}[/bold white]
[dim]{'─' * 40}[/dim]
[bold green]🎣 Advanced Phishing Detection Tool[/bold green]
[bold yellow]🔍 First Check, Then Click![/bold yellow]
"""
    
    panel = Panel(
        banner_text,
        title="[bold red]PhishScanner[/bold red]",
        border_style="cyan",
        padding=(1, 2)
    )
    console.print(panel)


def parse_arguments() -> argparse.Namespace:
    """Parse and validate command line arguments."""
    parser = argparse.ArgumentParser(
        prog='PhishScanner.py',
        description='A comprehensive Python tool for detecting phishing websites.',
        epilog='Contact: iahmedelhabashy@gmail.com',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output for detailed analysis'
    )
    
    parser.add_argument(
        '-f', '--config',
        metavar="CONFIG_FILE",
        type=Path,
        help='Path to config.ini file containing API keys',
        default=DEFAULT_CONFIG_PATH
    )
    
    parser.add_argument(
        '-u', '--url',
        metavar="URL",
        help='Suspected URL to analyze for phishing threats',
        required=True
    )
    
    parser.add_argument(
        '--log-file',
        metavar="LOG_FILE",
        type=Path,
        help='Path to log file for detailed logging'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=30,
        help='Request timeout in seconds (default: 30)'
    )
    
    parser.add_argument(
        '--no-screenshot',
        action='store_true',
        help='Skip screenshot capture'
    )
    
    parser.add_argument(
        '--output-format',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    
    parser.add_argument(
        '--output-file',
        type=Path,
        help='Save results to file'
    )
    
    return parser.parse_args()


def load_configuration(config_path: Path) -> Tuple[Dict[str, str], bool]:
    """
    Load and validate API configuration from file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Tuple of (api_keys_dict, success_flag)
        
    Raises:
        ConfigurationError: If configuration is invalid
    """
    try:
        if not config_path.exists():
            logging.warning(f"Configuration file not found: {config_path}")
            return _get_default_config(), False
            
        config = configparser.ConfigParser()
        config.read(config_path)
        
        if 'APIs' not in config:
            raise ConfigurationError("Missing [APIs] section in configuration file")
            
        api_keys = {
            'abuse_ip_db': config['APIs'].get('ABUSEIPDB_API_KEY', ''),
            'urlscan_io': config['APIs'].get('URLSCAN_API_KEY', ''),
            'virustotal': config['APIs'].get('VIRUSTOTAL_API_KEY', '')
        }
        
        # Validate API keys format
        _validate_api_keys(api_keys)
        
        return api_keys, True
        
    except Exception as e:
        logging.error(f"Error loading configuration: {e}")
        return _get_default_config(), False


def _get_default_config() -> Dict[str, str]:
    """Get default empty configuration."""
    return {
        'abuse_ip_db': '',
        'urlscan_io': '',
        'virustotal': ''
    }


def _validate_api_keys(api_keys: Dict[str, str]) -> None:
    """
    Validate API key formats.
    
    Args:
        api_keys: Dictionary of API keys to validate
        
    Raises:
        ConfigurationError: If any API key has invalid format
    """
    # Basic validation - check for placeholder values
    placeholder_values = [
        'your_abuseipdb_api_key',
        'your_urlscan_api_key', 
        'your_virustotal_api_key',
        'ABUSE_APT_KEY',  # Typo in original config
        'VT_API_KEY',
        'URLSCAN_API_KEY'
    ]
    
    for service, key in api_keys.items():
        if key in placeholder_values:
            logging.warning(f"{service} API key appears to be a placeholder")


def check_api_service(service_name: str, api_key: str) -> bool:
    """
    Check if API key is configured properly.
    
    Args:
        service_name: Name of the service
        api_key: API key to check
        
    Returns:
        True if API key is valid, False otherwise
    """
    placeholder_values = [
        'your_abuseipdb_api_key',
        'your_urlscan_api_key', 
        'your_virustotal_api_key',
        'ABUSE_APT_KEY',
        'VT_API_KEY',
        'URLSCAN_API_KEY',
        ''
    ]
    
    if api_key in placeholder_values:
        printc(f"[red3][-][/red3] {service_name} API key missing or not configured!")
        return False
    return True


def format_defanged_url(url: str) -> str:
    """
    Clean defanged URL for display.
    
    Args:
        url: Defanged URL to clean
        
    Returns:
        Cleaned URL string
    """
    return url.replace('hxxps[://]', '').replace('hxxp[://]', '')


def run_phishing_analysis(
    detector: PhishDetector, 
    api_keys: Dict[str, str], 
    args: argparse.Namespace
) -> Dict[str, Any]:
    """
    Execute the complete phishing analysis workflow.
    
    Args:
        detector: PhishDetector instance
        api_keys: Dictionary of API keys
        args: Command line arguments
        
    Returns:
        Dictionary containing analysis results
    """
    results = {
        'url': detector.url,
        'defanged_url': detector.defanged_url,
        'timestamp': datetime.now().isoformat(),
        'checks': {}
    }
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        
        # Display target information
        printc(f"\n[bright_blue][*][/bright_blue] Target URL: [red3]{detector.defanged_url}[/red3]")
        printc("─" * BANNER_WIDTH)
        
        # URL redirections analysis
        task = progress.add_task("Analyzing URL redirections...", total=None)
        try:
            detector.get_url_redirections(args.verbose)
            results['checks']['redirections'] = {
                'status': 'completed',
                'redirections_count': len(detector.servers),
                'expanded_url': detector.expanded_url
            }
            
            if detector.url != detector.expanded_url and len(detector.expanded_url) > 60:
                printc(f"[spring_green2][+][/spring_green2] Destination URL: {detector.expanded_url}")
                
        except Exception as e:
            logging.error(f"Error in redirection analysis: {e}")
            results['checks']['redirections'] = {'status': 'failed', 'error': str(e)}
        finally:
            progress.remove_task(task)
        
        # Google Safe Browsing check
        task = progress.add_task("Checking Google Safe Browsing...", total=None)
        try:
            printc(f"\n[bright_blue][*][/bright_blue] Google Safe Browsing Database Check")
            printc("─" * 42)
            detector.check_google_safe_browsing()
            results['checks']['safe_browsing'] = {'status': 'completed'}
        except Exception as e:
            logging.error(f"Error in Safe Browsing check: {e}")
            results['checks']['safe_browsing'] = {'status': 'failed', 'error': str(e)}
        finally:
            progress.remove_task(task)
        
        # IP tracking domains check
        task = progress.add_task("Checking IP tracking domains...", total=None)
        try:
            printc(f"\n[bright_blue][*][/bright_blue] IP Tracking Domains Database Check")
            printc("─" * 42)
            detector.check_tracking_domain_name()
            results['checks']['ip_tracking'] = {'status': 'completed'}
        except Exception as e:
            logging.error(f"Error in IP tracking check: {e}")
            results['checks']['ip_tracking'] = {'status': 'failed', 'error': str(e)}
        finally:
            progress.remove_task(task)
        
        # URL shortener check
        task = progress.add_task("Checking URL shortener domains...", total=None)
        try:
            printc(f"\n[bright_blue][*][/bright_blue] URL Shortener Domains Database Check")
            printc("─" * 44)
            detector.check_url_shortener_domain()
            results['checks']['url_shortener'] = {'status': 'completed'}
        except Exception as e:
            logging.error(f"Error in URL shortener check: {e}")
            results['checks']['url_shortener'] = {'status': 'failed', 'error': str(e)}
        finally:
            progress.remove_task(task)
        
        # VirusTotal analysis
        task = progress.add_task("Analyzing with VirusTotal...", total=None)
        try:
            clean_url = format_defanged_url(detector.defanged_url)
            printc(f"\n[bright_blue][*][/bright_blue] VirusTotal Reports for [red3]{clean_url}[/red3]")
            printc("─" * 55)
            
            if check_api_service("VirusTotal", api_keys['virustotal']):
                detector.check_virustotal(detector.expanded_url or detector.url, api_keys['virustotal'], args.verbose)
                results['checks']['virustotal'] = {'status': 'completed'}
            else:
                results['checks']['virustotal'] = {'status': 'skipped', 'reason': 'API key not configured'}
        except Exception as e:
            logging.error(f"Error in VirusTotal check: {e}")
            results['checks']['virustotal'] = {'status': 'failed', 'error': str(e)}
        finally:
            progress.remove_task(task)
        
        # URLScan.io analysis
        task = progress.add_task("Analyzing with URLScan.io...", total=None)
        try:
            printc(f"\n[bright_blue][*][/bright_blue] URLScan.io Reports for [red3]{clean_url}[/red3]")
            printc("─" * 55)
            
            if check_api_service("URLScan.io", api_keys['urlscan_io']):
                detector.check_urlscan_io(detector.expanded_url or detector.url, api_keys['urlscan_io'], args.verbose)
                results['checks']['urlscan'] = {'status': 'completed'}
            else:
                results['checks']['urlscan'] = {'status': 'skipped', 'reason': 'API key not configured'}
        except Exception as e:
            logging.error(f"Error in URLScan.io check: {e}")
            results['checks']['urlscan'] = {'status': 'failed', 'error': str(e)}
        finally:
            progress.remove_task(task)
        
        # AbuseIPDB analysis
        task = progress.add_task("Checking AbuseIPDB...", total=None)
        try:
            printc(f"\n[bright_blue][*][/bright_blue] AbuseIPDB Reports for [red3]{detector.target_ip_address}[/red3]")
            printc("─" * 49)
            
            if check_api_service("AbuseIPDB", api_keys['abuse_ip_db']):
                if detector.target_ip_address == "0.0.0.0":
                    domain = detector._get_domain_name(detector.expanded_url or detector.url)
                    printc(f"[red3][-][/red3] Unable to resolve {domain}")
                    results['checks']['abuseipdb'] = {'status': 'failed', 'reason': 'Unable to resolve IP'}
                else:
                    detector.check_abuse_ip_db(detector.target_ip_address, api_keys['abuse_ip_db'], args.verbose)
                    results['checks']['abuseipdb'] = {'status': 'completed'}
            else:
                results['checks']['abuseipdb'] = {'status': 'skipped', 'reason': 'API key not configured'}
        except Exception as e:
            logging.error(f"Error in AbuseIPDB check: {e}")
            results['checks']['abuseipdb'] = {'status': 'failed', 'error': str(e)}
        finally:
            progress.remove_task(task)
        
        # WHOIS lookup
        task = progress.add_task("Performing WHOIS lookup...", total=None)
        try:
            printc(f"\n[bright_blue][*][/bright_blue] WHOIS Lookup for [red3]{detector.target_ip_address}[/red3]")
            printc("─" * 42)
            
            if detector.target_ip_address == "0.0.0.0":
                domain = detector._get_domain_name(detector.expanded_url or detector.url)
                printc(f"[red3][-][/red3] Unable to resolve {domain}")
                results['checks']['whois'] = {'status': 'failed', 'reason': 'Unable to resolve IP'}
            else:
                detector.get_whois_info(detector.target_ip_address, args.verbose)
                results['checks']['whois'] = {'status': 'completed'}
        except Exception as e:
            logging.error(f"Error in WHOIS lookup: {e}")
            results['checks']['whois'] = {'status': 'failed', 'error': str(e)}
        finally:
            progress.remove_task(task)
        
        # Screenshot capture
        if not args.no_screenshot:
            task = progress.add_task("Capturing screenshot...", total=None)
            try:
                printc(f"\n[bright_blue][*][/bright_blue] Real-time Screenshot Capture")
                printc("─" * 42)
                detector.webpage_illustration(auto_display=False)
                results['checks']['screenshot'] = {'status': 'completed'}
            except Exception as e:
                logging.error(f"Error capturing screenshot: {e}")
                results['checks']['screenshot'] = {'status': 'failed', 'error': str(e)}
            finally:
                progress.remove_task(task)
        else:
            results['checks']['screenshot'] = {'status': 'skipped', 'reason': 'Disabled by user'}
    
    # Add summary to results
    results['summary'] = detector.get_analysis_summary()
    
    return results


def save_results(results: Dict[str, Any], output_file: Path, output_format: str) -> None:
    """
    Save analysis results to file.
    
    Args:
        results: Analysis results dictionary
        output_file: Path to output file
        output_format: Output format ('json' or 'text')
    """
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        if output_format == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        else:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"PhishScanner Analysis Report\n")
                f.write(f"{'=' * 50}\n\n")
                f.write(f"URL: {results['url']}\n")
                f.write(f"Defanged URL: {results['defanged_url']}\n")
                f.write(f"Timestamp: {results['timestamp']}\n\n")
                
                f.write("Analysis Results:\n")
                f.write("-" * 20 + "\n")
                for check, result in results['checks'].items():
                    status = result['status']
                    f.write(f"{check.replace('_', ' ').title()}: {status}\n")
                    if 'error' in result:
                        f.write(f"  Error: {result['error']}\n")
                    if 'reason' in result:
                        f.write(f"  Reason: {result['reason']}\n")
        
        printc(f"[spring_green2][+][/spring_green2] Results saved to: {output_file}")
        
    except Exception as e:
        logging.error(f"Error saving results: {e}")
        printc(f"[red3][-][/red3] Failed to save results: {e}")


def display_completion_summary(results: Dict[str, Any]) -> None:
    """
    Display analysis completion summary.
    
    Args:
        results: Analysis results dictionary
    """
    current_time = datetime.now()
    date_str = current_time.strftime("%Y-%m-%d")
    time_str = current_time.strftime("%H:%M:%S")
    
    # Create summary table
    table = Table(title="Analysis Summary", show_header=True, header_style="bold magenta")
    table.add_column("Check", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Details", style="dim")
    
    for check, result in results['checks'].items():
        status = result['status']
        details = ""
        
        if status == 'completed':
            status_display = "[green]✓ Completed[/green]"
        elif status == 'failed':
            status_display = "[red]✗ Failed[/red]"
            details = result.get('error', result.get('reason', ''))
        elif status == 'skipped':
            status_display = "[yellow]⚠ Skipped[/yellow]"
            details = result.get('reason', '')
        else:
            status_display = f"[dim]{status}[/dim]"
        
        table.add_row(
            check.replace('_', ' ').title(),
            status_display,
            details[:50] + "..." if len(details) > 50 else details
        )
    
    console.print("\n")
    console.print(table)
    
    # Display completion message
    completion_panel = Panel(
        f"[bold green]✓ PhishScanner analysis completed![/bold green]\n"
        f"[bold blue]Target:[/bold blue] [red]{results['defanged_url']}[/red]\n"
        f"[bold blue]Finished at:[/bold blue] {date_str} {time_str}",
        title="[bold green]Analysis Complete[/bold green]",
        border_style="green"
    )
    console.print(completion_panel)


def main() -> None:
    """Main application entry point."""
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Setup logging
        setup_logging(args.verbose, args.log_file)
        
        # Display banner
        display_banner()
        
        # Load configuration
        try:
            api_keys, config_loaded = load_configuration(args.config)
            if not config_loaded:
                printc("[yellow][!][/yellow] Configuration issues detected. Some features may be unavailable.")
        except ConfigurationError as e:
            printc(f"[red3][!][/red3] Configuration error: {e}")
            api_keys = _get_default_config()
        
        # Initialize detector
        try:
            detector = PhishDetector(args.url)
        except InvalidURLError as e:
            printc(f"[red3][!][/red3] {e}")
            sys.exit(1)
        except Exception as e:
            printc(f"[red3][!][/red3] Failed to initialize detector: {e}")
            sys.exit(1)
        
        # Run analysis
        try:
            results = run_phishing_analysis(detector, api_keys, args)
        except KeyboardInterrupt:
            printc("\n[yellow][!][/yellow] Analysis interrupted by user")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Analysis failed: {e}")
            printc(f"[red3][!][/red3] Analysis failed: {e}")
            sys.exit(1)
        
        # Save results if requested
        if args.output_file:
            save_results(results, args.output_file, args.output_format)
        
        # Display completion summary
        display_completion_summary(results)
        
    except KeyboardInterrupt:
        printc("\n[yellow][!][/yellow] Application interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        printc(f"[red3][!][/red3] An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
