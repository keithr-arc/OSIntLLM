# OSIntLLM - NMap Integration Branch

This branch (`nmap-integration`) extends the core OSIntLLM functionality with comprehensive NMap network scanning capabilities and additional threat intelligence sources.

## New Features

### 1. NMap Integration
- **Integrated Network Scanning**: NMap scanning is now fully integrated into the main application menu
- **Preset Scanning Profiles**: Choose from pre-configured scanning profiles optimized for different use cases
- **Custom Arguments**: Advanced users can provide custom NMap arguments for specialized scans
- **Automatic Result Parsing**: NMap XML output is automatically parsed and formatted
- **LLM Analysis**: NMap results are automatically piped to LLM for AI-powered analysis alongside other OSINT data

### 2. Enhanced Threat Intelligence
The following threat intelligence sources have been added:

#### OpenAI/ChatGPT Integration
- Alternative LLM provider for OSINT analysis
- Falls back to Gemini if OpenAI is not available
- API Key: Set `OPENAI_API_KEY` in `.env`

#### AbuseIPDB Integration (Already in Main)
- IP reputation checking
- Abuse history tracking
- API Key: Set `ABUSEIPDB_API_KEY` in `.env`

#### Project Honeypot Integration
- Honeypot threat data
- Threat level classification
- Last seen tracking
- API Key: Set `PROJECTHONEYPOT_API_KEY` in `.env`
- Get key from: https://www.projecthoneypot.org/api.php

#### GreyNoise Integration
- IP threat intelligence and classification
- Community API access (free tier available)
- Tags and action tracking
- API Key: Set `GREYNOISE_API_KEY` in `.env`
- Get key from: https://www.greynoise.io/account/api

### 3. Interactive Menu System
The application now features an interactive menu that allows users to:
1. Perform standard OSINT scans
2. Perform OSINT scans with NMap integration
3. View available NMap scanning profiles
4. View available NMap switches and options
5. Exit the application

### 4. NMap Scanning Profiles

#### Quick Scan
- **Description**: Fast scan of common ports only
- **Command**: `-F --top-ports 100`
- **Estimated Time**: 1-2 minutes
- **Best For**: Quick reconnaissance, initial port discovery

#### Comprehensive Scan
- **Description**: Scan all ports with service and version detection
- **Command**: `-p- -sV -sC -O --osscan-guess`
- **Estimated Time**: 5-15 minutes
- **Best For**: Detailed port and service analysis

#### Vulnerability Scan
- **Description**: Scan for vulnerabilities using NSE scripts
- **Command**: `-sV --script vuln -p- --script-args unsafe=1`
- **Estimated Time**: 10-20 minutes
- **Best For**: Vulnerability discovery and assessment

#### Aggressive Scan
- **Description**: Aggressive scan with all detection and timing
- **Command**: `-p- -sV -sC -O --osscan-guess -A -T4`
- **Estimated Time**: 15-30 minutes
- **Best For**: Comprehensive network reconnaissance

#### Custom Arguments
- Provide your own NMap arguments for specialized scanning needs
- Full access to NMap's extensive switch library

### 5. Available NMap Switches

The application provides a comprehensive guide to NMap switches organized by category:

**Port Scanning Options**
- `-p <port ranges>` - Scan specified ports
- `-F` - Scan 100 most common ports (fast)
- `-r` - Scan ports consecutively
- `--top-ports <number>` - Scan top N most common ports

**Scan Types**
- `-sS` - TCP SYN stealth scan (requires root)
- `-sT` - TCP connect scan
- `-sU` - UDP scan
- `-sA` - TCP ACK scan
- `-sW` - TCP Window scan
- `-sN/-sF/-sX` - TCP Null/FIN/Xmas scan

**Service Detection**
- `-sV` - Version detection
- `-sR` - RPC scan
- `-O` - OS detection (requires root)
- `--osscan-guess` - Guess OS if detection fails

**Scripts & Modules**
- `-sC` - Run default NSE scripts
- `--script <name>` - Run specific NSE script
- `--script vuln` - Scan for vulnerabilities

**Timing & Performance**
- `-T0 to -T5` - Timing templates (paranoid to insane)
- `-T4` - Aggressive timing (default for fast networks)

**Output Options**
- `-oN <file>` - Normal output to file
- `-oX <file>` - XML output to file
- `-oG <file>` - Grepable output to file
- `-oA <file>` - All formats to file

**Host Discovery**
- `-Pn` - Treat all hosts as online (skip ping)
- `-PS/PA/PU` - Use TCP SYN/ACK or UDP ping
- `-PE/PP/PM` - ICMP echo/timestamp/netmask ping

**Advanced Options**
- `-A` - Enable OS detection, version detection, script scanning
- `--traceroute` - Traceroute after port scan
- `--reason` - Show why port is in that state
- `--all-ports` - Do not exclude any ports from version detection

## Installation & Setup

### Prerequisites
- Python 3.10+
- NMap binary installed on system
  - **Linux/Ubuntu**: `sudo apt-get install nmap`
  - **macOS**: `brew install nmap`
  - **Windows**: Download from https://nmap.org/download.html

### Installation Steps

1. **Clone the repository and switch to the nmap-integration branch**
   ```bash
   git clone https://github.com/keithr-arc/OSIntLLM.git
   cd OSIntLLM
   git checkout nmap-integration
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure API Keys**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

4. **Verify NMap Installation**
   ```bash
   nmap --version
   ```

### API Keys Required

**Minimum Required (for standard OSINT)**
- `GEMINI_API_KEY` - https://makersuite.google.com/app/apikey
- `IPINFO_API_KEY` - https://ipinfo.io/account/token
- `SHODAN_API_KEY` - https://www.shodan.io/account/profile
- `CENSYS_API_ID` & `CENSYS_API_SECRET` - https://censys.io/account/api

**Optional (for enhanced threat intelligence)**
- `OPENAI_API_KEY` - https://platform.openai.com/account/api-keys
- `ABUSEIPDB_API_KEY` - https://www.abuseipdb.com/api
- `PROJECTHONEYPOT_API_KEY` - https://www.projecthoneypot.org/api.php
- `GREYNOISE_API_KEY` - https://www.greynoise.io/account/api

**No API Keys Required**
- NMap (binary installation required)
- WHOIS lookups (DNS resolution)
- SSL/TLS certificate analysis

## Usage

### Starting the Application
```bash
python osint_llm.py
```

### Main Menu Options

**Option 1: Standard OSINT Scan**
- Performs all standard OSINT data gathering without NMap
- Includes: IPInfo, Shodan, Censys, SSL, DNS, WHOIS, Threat Intelligence
- LLM analysis with Gemini or OpenAI

**Option 2: OSINT Scan + NMap**
- Combines all standard OSINT with NMap network scanning
- Choose from preset profiles or provide custom arguments
- All results are automatically analyzed by LLM
- Exported to both JSON and Markdown formats

**Option 3: View NMap Profiles**
- Displays all available scanning profiles
- Shows profile names, descriptions, and estimated time
- Helps users choose appropriate scanning strategy

**Option 4: View NMap Switches**
- Complete reference of NMap command-line switches
- Organized by category for easy navigation
- Supports creating custom scan arguments

**Option 5: Exit**
- Gracefully exits the application

### Example Usage Flow

```
1. Start application: python osint_llm.py
2. Select Option 2 (OSINT + NMap)
3. Enter target: 8.8.8.8
4. Select NMap profile: 2 (Comprehensive)
5. Wait for scan to complete
6. Results saved as:
   - osint_scan_8.8.8.8_[timestamp].json
   - osint_scan_8.8.8.8_[timestamp].md
```

## Output Files

### JSON Output
Complete structured data in JSON format:
- All OSINT sources (IPInfo, Shodan, Censys, SSL, DNS, WHOIS)
- Threat intelligence (VirusTotal, AbuseIPDB, Project Honeypot, GreyNoise)
- NMap scanning results (ports, services, OS detection)
- LLM analysis
- Scan metadata and summary

### Markdown Output
Human-readable report with:
- Target information and scan date
- Detailed findings from each OSINT source
- NMap results with port/service information
- LLM analysis and recommendations
- Executive summary

## Architecture

### Core Components

**osint_llm.py** - Main application
- OSIntLLM class: Handles all OSINT gathering
- Target normalization and validation
- LLM integration (Gemini and OpenAI)
- Menu system and user interaction
- Result formatting and export

**nmap_integration.py** - NMap module
- NMapScanner class: Manages network scanning
- Scan profiles and preset configurations
- XML result parsing
- Switch documentation
- Result formatting

**config.py** - Configuration management
- APIConfig dataclass: Centralized API key management
- Configuration validation
- All API credentials from .env file

**.env.example** - Environment template
- All configurable API keys with documentation
- Links to obtain credentials
- Optional timeout and retry settings

**requirements.txt** - Python dependencies
- All required packages for full functionality
- Version specifications for stability
- Optional packages for advanced features

## Key Features

### 1. Intelligent Target Detection
- Automatically identifies IP addresses, FQDNs, domains, and URLs
- Resolves hostnames to IP addresses when needed
- Validates targets before scanning

### 2. Integrated LLM Analysis
- OpenAI/ChatGPT support (primary)
- Google Gemini fallback
- Automatic analysis of all OSINT and NMap data
- Professional security recommendations

### 3. Multiple Threat Intelligence Sources
- **VirusTotal**: Malware and file hash analysis
- **AbuseIPDB**: IP abuse tracking
- **Project Honeypot**: Honeypot threat data
- **GreyNoise**: IP classification and threat tags
- All sources combined for comprehensive threat assessment

### 4. Comprehensive Export Options
- JSON format for programmatic use
- Markdown format for reports
- Automatic filename generation with timestamps
- Graceful error handling

### 5. Professional Security Analysis
- Vulnerability identification
- Risk assessment
- Remediation recommendations
- Advanced investigation suggestions

## Security Considerations

### Important Notes
- **API Key Security**: Never commit `.env` files to version control
- **Root Privileges**: Some NMap scans (OS detection) require elevated privileges
- **Network Permissions**: Ensure you have authorization before scanning
- **Rate Limiting**: Respect API rate limits of threat intelligence services
- **Responsible Use**: Only scan systems you own or have explicit permission to scan

### Best Practices
1. Store API keys securely in `.env` file
2. Restrict `.env` file permissions (chmod 600)
3. Use least privilege for NMap scans
4. Monitor API quota usage
5. Validate targets before scanning
6. Review scan results for accuracy

## Troubleshooting

### NMap Not Found
```
Error: NMap is not installed or not available in PATH
```
**Solution**: Install NMap following installation instructions above

### API Key Errors
```
Warning: Missing required API keys
```
**Solution**: Add missing API keys to `.env` file

### Permission Denied for OS Detection
```
Operation requires root privileges
```
**Solution**: Run with `sudo` or use non-privileged scans

### Timeout Issues
**Solution**: Increase TIMEOUT value in `.env`:
```
TIMEOUT=60
```

### Rate Limiting
**Solution**: Increase REQUEST_DELAY in `.env`:
```
REQUEST_DELAY=2.0
```

## Development Notes

### Adding New Threat Intelligence Sources
1. Add API key to `config.py` APIConfig class
2. Create `_query_<source>()` method in `OSIntLLM` class
3. Add to `get_threat_intelligence()` method
4. Update `.env.example` with documentation

### Extending NMap Profiles
1. Add new profile to `SCAN_PROFILES` dict in `NMapScanner`
2. Define profile name, description, args, and time estimate
3. Profile automatically available in menu

### Custom Scanning Scripts
Users can provide custom NMap arguments in the interactive menu or extend the code with additional profiles.

## Integration with Main Branch

This branch (`nmap-integration`) can be merged into main with:
- All features backward compatible
- NMap is optional (graceful degradation if not installed)
- Standard OSINT scans work without NMap
- Additional threat intelligence sources are optional

## Future Enhancements

Potential future additions:
- Metasploit integration
- Shodan CLI queries
- Certificate transparency logs
- BGP routing analysis
- Social media OSINT
- Subdomain enumeration
- DNS brute force capabilities
- Batch target scanning
- Database persistence
- Web UI dashboard

## Support & Contributions

For issues, questions, or contributions:
1. Check existing GitHub issues
2. Review this documentation
3. Test with your API keys and network
4. Submit detailed bug reports with logs

## License

Same as main OSIntLLM repository

## References

- NMap Official: https://nmap.org/
- OWASP Network Scanning: https://owasp.org/
- Shodan API: https://shodan.io/
- Censys API: https://censys.io/
- IPInfo.io: https://ipinfo.io/
- AbuseIPDB: https://www.abuseipdb.com/
- Project Honeypot: https://www.projecthoneypot.org/
- GreyNoise: https://www.greynoise.io/
