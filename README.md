# PhishScanner v2.0

A comprehensive Python tool for detecting phishing websites using multiple detection methods and APIs.

## 🚀 What's New in v2.0

### Major Improvements
- **Complete code refactoring** with proper type hints and documentation
- **Enhanced error handling** with custom exception classes
- **Caching system** for improved performance and reduced API calls
- **Configuration validation** with schema checking
- **Comprehensive test suite** with unit and integration tests
- **Better CLI interface** with progress indicators and rich output
- **Modular architecture** with separated concerns
- **Performance optimizations** with concurrent requests and connection pooling

### New Features
- **JSON output format** for programmatic usage
- **Results saving** to files with multiple formats
- **Advanced logging** with file rotation and structured output
- **Cache management** with persistent storage and TTL
- **Configuration validation** with detailed error reporting
- **Progress indicators** for long-running operations
- **Enhanced screenshot capture** with better error handling
- **Improved URL validation** and sanitization

## 📋 Requirements

- Python 3.8+
- Internet connection for API calls
- Required Python packages (see `requirements.txt`)

## 🛠 Installation

1. Clone the repository:
```bash
git clone https://github.com/0x4hm3d/PhishScanner.git
cd PhishScanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure API keys:
```bash
cp config/config.ini.sample config/config.ini
# Edit config/config.ini with your API keys
```

## 🔧 Configuration

### API Keys Setup

1. **AbuseIPDB**: Get your API key from [AbuseIPDB](https://www.abuseipdb.com/api)
2. **VirusTotal**: Get your API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
3. **URLScan.io**: Get your API key from [URLScan.io](https://urlscan.io/user/signup)

### Configuration File Structure

The configuration file (`config/config.ini`) contains several sections:

- **[APIs]**: API keys for external services
- **[Settings]**: General application settings
- **[Detection]**: Detection-specific settings
- **[Output]**: Output formatting options
- **[Performance]**: Performance tuning parameters

### Configuration Validation

Validate your configuration file:
```bash
python config_validator.py config/config.ini
```

Create a sample configuration:
```bash
python config_validator.py --create-sample config/config.ini.sample
```

## 🚀 Usage

### Basic Usage

```bash
python PhishScanner.py -u https://suspicious-website.com
```

### Advanced Usage

```bash
# Verbose output with detailed analysis
python PhishScanner.py -u https://example.com --verbose

# Save results to JSON file
python PhishScanner.py -u https://example.com --output-format json --output-file results.json

# Custom configuration file
python PhishScanner.py -u https://example.com --config /path/to/config.ini

# Skip screenshot capture
python PhishScanner.py -u https://example.com --no-screenshot

# Enable logging to file
python PhishScanner.py -u https://example.com --log-file phishscanner.log
```

### Command Line Options

```
usage: PhishScanner.py [-h] [-v] [-f CONFIG_FILE] [-u URL] [--log-file LOG_FILE]
                       [--timeout TIMEOUT] [--no-screenshot]
                       [--output-format {text,json}] [--output-file OUTPUT_FILE]

A comprehensive Python tool for detecting phishing websites.

required arguments:
  -u URL, --url URL     Suspected URL to analyze for phishing threats

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbose output for detailed analysis
  -f CONFIG_FILE, --config CONFIG_FILE
                        Path to config.ini file containing API keys
  --log-file LOG_FILE   Path to log file for detailed logging
  --timeout TIMEOUT     Request timeout in seconds (default: 30)
  --no-screenshot       Skip screenshot capture
  --output-format {text,json}
                        Output format (default: text)
  --output-file OUTPUT_FILE
                        Save results to file
```

## 🔍 Detection Methods

PhishScanner uses multiple detection methods:

1. **URL Redirection Analysis**: Tracks URL redirections and analyzes the chain
2. **Google Safe Browsing**: Checks against Google's Safe Browsing database
3. **IP Tracking Domains**: Identifies known IP tracking domains
4. **URL Shortener Detection**: Detects shortened URLs
5. **VirusTotal Analysis**: Comprehensive malware and phishing detection
6. **URLScan.io Analysis**: Real-time website analysis and screenshots
7. **AbuseIPDB Check**: IP reputation analysis
8. **WHOIS Lookup**: Domain registration information
9. **Screenshot Capture**: Visual analysis of the website

## 📊 Output Formats

### Text Output (Default)
Human-readable format with colored output and progress indicators.

### JSON Output
Structured data format suitable for programmatic processing:

```json
{
  "url": "https://example.com",
  "defanged_url": "hxxps[://]example[.]com",
  "timestamp": "2024-01-01T12:00:00",
  "checks": {
    "redirections": {"status": "completed", "redirections_count": 1},
    "safe_browsing": {"status": "completed"},
    "virustotal": {"status": "completed"},
    "urlscan": {"status": "completed"},
    "abuseipdb": {"status": "completed"},
    "whois": {"status": "completed"},
    "screenshot": {"status": "completed"}
  },
  "summary": {
    "domain": "example.com",
    "target_ip": "192.0.2.1",
    "has_screenshot": true
  }
}
```

## 🗄 Database Files

PhishScanner uses several database files for offline detection:

- `db/user_agents.db`: User agent strings for request rotation
- `db/ip_tracking_domains.json`: Known IP tracking domains
- `db/url_shortener_domains.db`: Known URL shortener domains

These files are automatically loaded and validated on startup.

## 🧪 Testing

Run the comprehensive test suite:

```bash
python test_phishscanner.py
```

Run specific test categories:

```bash
# Unit tests only
python -m unittest test_phishscanner.TestPhishDetector

# Integration tests
python -m unittest test_phishscanner.TestIntegration

# Configuration tests
python -m unittest test_phishscanner.TestConfigValidator
```

## 📈 Performance Features

### Caching System
- **Memory caching**: Fast access to recently used data
- **Persistent caching**: Disk-based storage for long-term caching
- **TTL support**: Automatic expiration of cached data
- **Cache management**: Tools for cache statistics and cleanup

### Concurrent Processing
- **Parallel API requests**: Multiple requests processed simultaneously
- **Connection pooling**: Reuse of HTTP connections
- **Rate limiting**: Respect API rate limits
- **Retry logic**: Automatic retry on transient failures

### Cache Management

```bash
# View cache statistics
python cache_manager.py --stats

# Clear all cached data
python cache_manager.py --clear

# Specify custom cache directory
python cache_manager.py --cache-dir /path/to/cache --stats
```

## 🔧 Development

### Project Structure

```
PhishScanner/
├── PhishScanner.py          # Main application entry point
├── phish_detector.py        # Core detection logic
├── config_validator.py      # Configuration validation
├── cache_manager.py         # Caching system
├── test_phishscanner.py     # Test suite
├── requirements.txt         # Python dependencies
├── config/
│   └── config.ini          # Configuration file
├── db/                     # Database files
│   ├── user_agents.db
│   ├── ip_tracking_domains.json
│   └── url_shortener_domains.db
└── logs/                   # Log files (created automatically)
```

### Code Quality

The codebase follows Python best practices:

- **Type hints**: Full type annotation coverage
- **Documentation**: Comprehensive docstrings
- **Error handling**: Proper exception handling with custom exceptions
- **Logging**: Structured logging with multiple levels
- **Testing**: Unit tests and integration tests
- **Code organization**: Modular design with separated concerns

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with proper tests
4. Ensure all tests pass
5. Submit a pull request

## 🐛 Troubleshooting

### Common Issues

1. **API Key Errors**
   - Verify API keys are correctly configured
   - Check API key format using the validator
   - Ensure API keys have proper permissions

2. **Network Timeouts**
   - Increase timeout values in configuration
   - Check internet connectivity
   - Verify firewall settings

3. **Database File Errors**
   - Ensure database files exist in the `db/` directory
   - Check file permissions
   - Verify file formats are correct

4. **Cache Issues**
   - Clear cache using cache manager
   - Check disk space for persistent cache
   - Verify cache directory permissions

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
python PhishScanner.py -u https://example.com --verbose --log-file debug.log
```

### Configuration Validation

Validate your configuration before running:

```bash
python config_validator.py config/config.ini
```

## 📝 Changelog

### v2.0.0 (Current)
- Complete rewrite with modern Python practices
- Added comprehensive caching system
- Enhanced error handling and logging
- Improved CLI interface with rich output
- Added configuration validation
- Comprehensive test suite
- Performance optimizations
- Better documentation

### v1.0.0 (Previous)
- Initial release
- Basic phishing detection functionality
- Simple CLI interface

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Author

**0x4hm3d**
- X:: @iahmedelhabashy
- GitHub: [0x4hm3d](https://github.com/0x4hm3d)

## 🙏 Acknowledgments

- Thanks to all API providers (AbuseIPDB, VirusTotal, URLScan.io)

## ⚠️ Disclaimer

This tool is for educational and security research purposes only. Users are responsible for complying with applicable laws and terms of service of the APIs used. The authors are not responsible for any misuse of this tool.

---

**🔍 First Check, Then Click!**

