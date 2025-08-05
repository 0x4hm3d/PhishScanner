#!/usr/bin/env python3
"""
Configuration validation module for PhishScanner.

This standalone script validates the 'config.ini' file using Pydantic schemas
to ensure all API keys and settings are correctly formatted. It can also be
used to generate a sample configuration file.

Author: 0x4hm3d
Version: 2.2 (Revised)
"""

import re
import sys
import configparser
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

# This script has an optional dependency on Pydantic.
# If not installed, some validation will be skipped.
try:
    from pydantic import BaseModel, field_validator, ValidationError
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False

from rich import print as printc
from rich.panel import Panel

# --- Pydantic Models for Validation (if available) ---

if PYDANTIC_AVAILABLE:
    class APIKeyConfig(BaseModel):
        """Pydantic model for validating the [APIs] section of the config."""
        abuse_ip_db: str = ""
        urlscan_io: str = ""
        virustotal: str = ""

        @field_validator('abuse_ip_db')
        def validate_abuseipdb_key(cls, v):
            """Validate AbuseIPDB API key format (optional check)."""
            if v and not re.match(r'^[a-f0-9]{40,100}$', v): # More flexible length
                logging.warning("AbuseIPDB API key format appears unusual.")
            return v

        @field_validator('virustotal')
        def validate_virustotal_key(cls, v):
            """Validate VirusTotal API key format (optional check)."""
            if v and not re.match(r'^[a-f0-9]{64}$', v):
                logging.warning("VirusTotal API key format appears invalid (expected 64 hex chars).")
            return v

        @field_validator('urlscan_io')
        def validate_urlscan_key(cls, v):
            """Validate URLScan.io API key format (optional check)."""
            if v and not re.match(r'^[a-f0-9-]{36}$', v):
                logging.warning("URLScan.io API key format appears invalid (expected UUID format).")
            return v

    class AppConfig(BaseModel):
        """Pydantic model for validating the [Settings] section of the config."""
        timeout: int = 30
        log_level: str = "INFO"

        @field_validator('timeout')
        def validate_timeout(cls, v):
            """Validate timeout value is within a reasonable range."""
            if not 1 <= v <= 300:
                raise ValueError("Timeout must be between 1 and 300 seconds.")
            return v

        @field_validator('log_level')
        def validate_log_level(cls, v):
            """Validate the log level string."""
            valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            if v.upper() not in valid_levels:
                raise ValueError(f"Log level must be one of: {', '.join(valid_levels)}")
            return v.upper()

# --- Main Validator Class ---

class ConfigValidator:
    """
    Validates the PhishScanner config.ini file for structural integrity,
    required sections, and valid values.
    """
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
        if not PYDANTIC_AVAILABLE:
            self.logger.warning("Pydantic is not installed. Advanced validation will be skipped. Run 'pip install pydantic'.")

    def validate_config_file(self, config_path: Path) -> None:
        """
        Orchestrates the validation of a given config.ini file and prints the results.
        
        Args:
            config_path: The path to the config.ini file.
        """
        errors = []
        warnings = []

        if not config_path.exists():
            printc(Panel(f"[bold red]Error:[/] Configuration file not found at '[cyan]{config_path}[/cyan]'.",
                         title="[bold red]Validation Failed[/]", border_style="red"))
            sys.exit(1)

        try:
            config = configparser.ConfigParser()
            config.read(config_path)

            # Basic structural validation
            if 'APIs' not in config:
                errors.append("Configuration is missing the required '[APIs]' section.")
            else:
                self._validate_apis_section(config, errors, warnings)
            
            if 'Settings' in config:
                self._validate_settings_section(config, errors)

        except configparser.Error as e:
            errors.append(f"Failed to parse the configuration file: {e}")

        # --- Print Results ---
        printc(Panel(f"Validation results for '[cyan]{config_path}[/cyan]'",
                     title="[bold]Configuration Check[/]", border_style="blue"))

        if errors:
            printc("[bold red]Errors Found:[/]")
            for error in errors:
                printc(f"  [red]✗ {error}[/red]")
        
        if warnings:
            printc("\n[bold yellow]Warnings:[/]")
            for warning in warnings:
                printc(f"  [yellow]⚠ {warning}[/yellow]")

        if not errors:
            printc("\n[bold green]✓ Configuration appears to be valid![/bold green]")
        else:
            printc("\n[bold red]✗ Configuration has errors that must be fixed.[/bold red]")

    def _validate_apis_section(self, config: configparser.ConfigParser, errors: list, warnings: list):
        """Validates the [APIs] section."""
        api_keys = {
            'abuse_ip_db': config['APIs'].get('ABUSEIPDB_API_KEY', ''),
            'urlscan_io': config['APIs'].get('URLSCAN_API_KEY', ''),
            'virustotal': config['APIs'].get('VIRUSTOTAL_API_KEY', '')
        }

        # Check for empty or placeholder keys
        for service, key in api_keys.items():
            if not key:
                warnings.append(f"The API key for '{service}' is empty. Related checks will be skipped.")
            elif "your_" in key or "_KEY_HERE" in key:
                warnings.append(f"The API key for '{service}' appears to be a placeholder.")
        
        # Advanced validation with Pydantic if available
        if PYDANTIC_AVAILABLE:
            try:
                APIKeyConfig(**api_keys)
            except ValidationError as e:
                for error in e.errors():
                    errors.append(f"[APIs] - {error['loc'][0]}: {error['msg']}")

    def _validate_settings_section(self, config: configparser.ConfigParser, errors: list):
        """Validates the [Settings] section."""
        if not PYDANTIC_AVAILABLE:
            return # Skip if pydantic is not installed

        try:
            settings_data = {
                'timeout': config['Settings'].getint('timeout', 30),
                'log_level': config['Settings'].get('log_level', 'INFO')
            }
            AppConfig(**settings_data)
        except ValueError as e: # Catches getint errors
            errors.append(f"[Settings] - Invalid integer value provided. {e}")
        except ValidationError as e:
            for error in e.errors():
                errors.append(f"[Settings] - {error['loc'][0]}: {error['msg']}")

    def create_sample_config(self, output_path: Path) -> bool:
        """
        Creates a sample config.ini file with comments and placeholders.
        
        Args:
            output_path: The path where the file should be created.
            
        Returns:
            True if creation was successful, False otherwise.
        """
        sample_config = """[APIs]
# --- API Keys (Required for full functionality) ---

# Get your key from: https://www.abuseipdb.com/account/api
ABUSEIPDB_API_KEY = your_abuseipdb_api_key_here

# Get your key from: https://urlscan.io/user/signup
URLSCAN_API_KEY = your_urlscan_api_key_here

# Get your key from: https://www.virustotal.com/gui/join-us
VIRUSTOTAL_API_KEY = your_virustotal_api_key_here

[Settings]
# --- Optional Application Settings ---

# Request timeout in seconds (e.g., 30)
timeout = 30

# Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
log_level = INFO
"""
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(sample_config.strip(), encoding='utf-8')
            printc(Panel(f"Sample configuration file created successfully at:\n[cyan]{output_path.resolve()}[/cyan]",
                         title="[bold green]Sample Created[/]", border_style="green"))
            return True
        except IOError as e:
            printc(Panel(f"[bold red]Error:[/] Could not write to file at '[cyan]{output_path}[/cyan]'.\nDetails: {e}",
                         title="[bold red]Creation Failed[/]", border_style="red"))
            return False

def main():
    """Provides a command-line interface for the validator."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="A validation tool for the PhishScanner config.ini file.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '--validate', 
        dest='config_file', 
        type=Path, 
        metavar='PATH',
        help='Path to the config.ini file to validate.'
    )
    group.add_argument(
        '--create-sample', 
        dest='sample_path', 
        type=Path, 
        metavar='PATH',
        help="Path to create a new, sample config.ini file (e.g., config/config.ini)."
    )
    
    args = parser.parse_args()
    validator = ConfigValidator()
    
    if args.sample_path:
        validator.create_sample_config(args.sample_path)
    elif args.config_file:
        validator.validate_config_file(args.config_file)

if __name__ == "__main__":
    main()
