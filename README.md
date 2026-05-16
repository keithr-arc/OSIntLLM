1. osint_llm.py - Main Application
A full-featured Python 3.10 tool with:

IPInfo.io Integration - Geolocation and ASN data for IP addresses
Shodan.io Integration - Port scanning, service detection, and vulnerability discovery
Censys Integration - Certificate discovery and autonomous system information
Google Gemini LLM - AI-powered analysis of all OSINT data
SSL/TLS Certificate Analysis - Retrieves and validates certificates
DNS Resolution - Queries A, AAAA, MX, NS, TXT, CNAME records
WHOIS Lookups - Domain registration and registrar information
Threat Intelligence - VirusTotal and AbuseIPDB integration
Multi-format Export - JSON and Markdown report generation
Smart Target Detection - Automatically identifies IP, domain, FQDN, or URL inputs
Robust Error Handling - Graceful failures with retry logic
2. config.py - Configuration Management
Centralized API key management via environment variables
Timeout and retry configuration
API validation with helpful error messages
Security-focused design with no hardcoded credentials
3. requirements.txt - Dependencies
All Python packages needed:

google-generativeai (Google Gemini)
shodan (Shodan API)
censys (Censys API)
dnspython (DNS queries)
python-whois (WHOIS lookups)
pyOpenSSL (SSL analysis)
requests (HTTP client)
python-dotenv (Environment management)
4. .env.example - Configuration Template
Sample environment file with:

API key placeholders for all required services
Links to obtain each API key
Optional API configurations
Helpful comments
Key Capabilities:
✅ Scan Target Types: IP addresses, domains, FQDNs, and full URLs ✅ Vulnerability Detection: Open ports, certificate issues, DNS misconfigurations ✅ AI Analysis: Google Gemini provides intelligent security assessment ✅ Batch Processing: Scan multiple targets in one session ✅ Professional Reports: Export findings in JSON or Markdown format ✅ Rate Limiting: Configurable delays to respect API quotas ✅ Interactive CLI: Easy-to-use command-line interface ✅ Programmatic API: Use as a Python library in your own code

Usage Example:

# Install dependencies
pip install -r requirements.txt

# Configure API keys
cp .env.example .env
# Edit .env with your API keys

# Run the tool
python osint_llm.py

The application will prompt you to enter targets and automatically:

Resolve hostnames to IP addresses
Gather data from all OSINT sources
Analyze findings with Google Gemini AI
Export professional security reports
All API keys are managed securely through environment variables, and the tool includes comprehensive error handling for missing or invalid credentials.
