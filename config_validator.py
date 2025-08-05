#!/usr/bin/env python3
"""
Configuration validation module for PhishScanner.

This module provides configuration validation and schema checking
for API keys and application settings.

Author: 0x4hm3d
Version: 2.0
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import configparser
import logging

from pydantic import BaseModel, validator, ValidationError


class APIKeyConfig(BaseModel):
    """Configuration model for API keys."""
    
    abuse_ip_db: str = ""
    urlscan_io: str = ""
    virustotal: str = ""
    
    @validator('abuse_ip_db')
    def validate_abuseipdb_key(cls, v):
        """Validate AbuseIPDB API key format."""
        if v and not re.match(r'^[a-f0-9]{80}$', v):
            logging.warning("AbuseIPDB API key format may be invalid (expected 80 hex chars)")
        return v
    
    @validator('virustotal')
    def validate_virustotal_key(cls, v):
        """Validate VirusTotal API key format."""
        if v and not re.match(r'^[a-f0-9]{64}$', v):
            logging.warning("VirusTotal API key format may be invalid (expected 64 hex chars)")
        return v
    
    @validator('urlscan_io')
    def validate_urlscan_key(cls, v):
        """Validate URLScan.io API key format."""
        if v and not re.match(r'^[a-f0-9-]{36}$', v):
            logging.warning("URLScan.io API key format may be invalid (expected UUID format)")
        return v


class AppConfig(BaseModel):
    """Configuration model for application settings."""
    
    timeout: int = 30
    max_redirects: int = 10
    user_agent_rotation: bool = True
    cache_enabled: bool = True
    cache_ttl: int = 3600
    log_level: str = "INFO"
    
    @validator('timeout')
    def validate_timeout(cls, v):
        """Validate timeout value."""
        if v < 1 or v > 300:
            raise ValueError("Timeout must be between 1 and 300 seconds")
        return v
    
    @validator('max_redirects')
    def validate_max_redirects(cls, v):
        """Validate max redirects value."""
        if v < 0 or v > 50:
            raise ValueError("Max redirects must be between 0 and 50")
        return v
    
    @validator('cache_ttl')
    def validate_cache_ttl(cls, v):
        """Validate cache TTL value."""
        if v < 0 or v > 86400:  # 24 hours max
            raise ValueError("Cache TTL must be between 0 and 86400 seconds")
        return v
    
    @validator('log_level')
    def validate_log_level(cls, v):
        """Validate log level."""
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {', '.join(valid_levels)}")
        return v.upper()


@dataclass
class ConfigValidationResult:
    """Result of configuration validation."""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    config: Optional[Dict[str, Any]] = None


class ConfigValidator:
    """Configuration validator for PhishScanner."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def validate_config_file(self, config_path: Path) -> ConfigValidationResult:
        """
        Validate configuration file.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            ConfigValidationResult with validation status and details
        """
        errors = []
        warnings = []
        config_data = {}
        
        try:
            # Check if file exists
            if not config_path.exists():
                errors.append(f"Configuration file not found: {config_path}")
                return ConfigValidationResult(False, errors, warnings)
            
            # Parse configuration file
            config = configparser.ConfigParser()
            config.read(config_path)
            
            # Validate structure
            if 'APIs' not in config:
                errors.append("Missing [APIs] section in configuration file")
            else:
                # Extract API keys
                api_config_data = {
                    'abuse_ip_db': config['APIs'].get('ABUSEIPDB_API_KEY', ''),
                    'urlscan_io': config['APIs'].get('URLSCAN_API_KEY', ''),
                    'virustotal': config['APIs'].get('VIRUSTOTAL_API_KEY', '')
                }
                
                # Validate API keys
                try:
                    api_config = APIKeyConfig(**api_config_data)
                    config_data['apis'] = api_config.dict()
                except ValidationError as e:
                    for error in e.errors():
                        errors.append(f"API key validation error: {error['msg']}")
            
            # Validate app settings if present
            if 'Settings' in config:
                app_config_data = {
                    'timeout': config['Settings'].getint('timeout', 30),
                    'max_redirects': config['Settings'].getint('max_redirects', 10),
                    'user_agent_rotation': config['Settings'].getboolean('user_agent_rotation', True),
                    'cache_enabled': config['Settings'].getboolean('cache_enabled', True),
                    'cache_ttl': config['Settings'].getint('cache_ttl', 3600),
                    'log_level': config['Settings'].get('log_level', 'INFO')
                }
                
                try:
                    app_config = AppConfig(**app_config_data)
                    config_data['settings'] = app_config.dict()
                except ValidationError as e:
                    for error in e.errors():
                        errors.append(f"Settings validation error: {error['msg']}")
            
            # Check for placeholder values
            self._check_placeholder_values(config_data.get('apis', {}), warnings)
            
        except Exception as e:
            errors.append(f"Error reading configuration file: {e}")
        
        is_valid = len(errors) == 0
        return ConfigValidationResult(is_valid, errors, warnings, config_data)
    
    def _check_placeholder_values(self, api_config: Dict[str, str], warnings: List[str]) -> None:
        """Check for placeholder API key values."""
        placeholder_patterns = [
            'your_.*_api_key',
            '.*_API_KEY',
            'ABUSE_APT_KEY',  # Common typo
            'VT_API_KEY',
            'URLSCAN_API_KEY'
        ]
        
        for service, key in api_config.items():
            if not key:
                warnings.append(f"{service} API key is empty")
                continue
                
            for pattern in placeholder_patterns:
                if re.match(pattern, key, re.IGNORECASE):
                    warnings.append(f"{service} API key appears to be a placeholder: {key}")
                    break
    
    def create_sample_config(self, output_path: Path) -> bool:
        """
        Create a sample configuration file.
        
        Args:
            output_path: Path where to create the sample config
            
        Returns:
            True if successful, False otherwise
        """
        try:
            sample_config = """[APIs]
# AbuseIPDB API Key (80 hex characters)
# Get your key from: https://www.abuseipdb.com/api
ABUSEIPDB_API_KEY = your_abuseipdb_api_key_here

# URLScan.io API Key (UUID format)
# Get your key from: https://urlscan.io/user/signup
URLSCAN_API_KEY = your_urlscan_api_key_here

# VirusTotal API Key (64 hex characters)
# Get your key from: https://www.virustotal.com/gui/join-us
VIRUSTOTAL_API_KEY = your_virustotal_api_key_here

[Settings]
# Request timeout in seconds (1-300)
timeout = 30

# Maximum number of redirects to follow (0-50)
max_redirects = 10

# Enable user agent rotation
user_agent_rotation = true

# Enable caching of results
cache_enabled = true

# Cache time-to-live in seconds (0-86400)
cache_ttl = 3600

# Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
log_level = INFO
"""
            
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(sample_config)
            
            self.logger.info(f"Sample configuration created at: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating sample config: {e}")
            return False
    
    def validate_api_key_format(self, service: str, api_key: str) -> bool:
        """
        Validate API key format for specific service.
        
        Args:
            service: Service name (abuseipdb, virustotal, urlscan)
            api_key: API key to validate
            
        Returns:
            True if format is valid, False otherwise
        """
        if not api_key:
            return False
        
        patterns = {
            'abuseipdb': r'^[a-f0-9]{80}$',
            'virustotal': r'^[a-f0-9]{64}$',
            'urlscan': r'^[a-f0-9-]{36}$'
        }
        
        pattern = patterns.get(service.lower())
        if not pattern:
            return False
        
        return bool(re.match(pattern, api_key))


def main():
    """CLI interface for configuration validation."""
    import argparse
    
    parser = argparse.ArgumentParser(description="PhishScanner Configuration Validator")
    parser.add_argument('config_file', type=Path, help='Configuration file to validate')
    parser.add_argument('--create-sample', type=Path, help='Create sample configuration file')
    
    args = parser.parse_args()
    
    validator = ConfigValidator()
    
    if args.create_sample:
        if validator.create_sample_config(args.create_sample):
            print(f"Sample configuration created: {args.create_sample}")
        else:
            print("Failed to create sample configuration")
        return
    
    result = validator.validate_config_file(args.config_file)
    
    print(f"Configuration validation for: {args.config_file}")
    print(f"Valid: {'✓' if result.is_valid else '✗'}")
    
    if result.errors:
        print("\nErrors:")
        for error in result.errors:
            print(f"  - {error}")
    
    if result.warnings:
        print("\nWarnings:")
        for warning in result.warnings:
            print(f"  - {warning}")
    
    if result.is_valid:
        print("\n✓ Configuration is valid!")
    else:
        print("\n✗ Configuration has errors that need to be fixed.")


if __name__ == "__main__":
    main()