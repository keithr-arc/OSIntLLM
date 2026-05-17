#!/usr/bin/env python3
"""
OSIntLLM NMap Integration - Quick Start Guide
This file serves as both documentation and an example setup helper
"""

"""
QUICK START GUIDE - NMap Integration Branch
=============================================

1. INSTALLATION (5 minutes)
---------------------------

Step 1: Install NMap Binary
  Linux/Ubuntu:
    $ sudo apt-get update
    $ sudo apt-get install nmap
  
  macOS:
    $ brew install nmap
  
  Windows:
    Download from https://nmap.org/download.html
    Or use: choco install nmap

Step 2: Clone and Setup Repository
  $ git clone https://github.com/keithr-arc/OSIntLLM.git
  $ cd OSIntLLM
  $ git checkout nmap-integration
  $ pip install -r requirements.txt

Step 3: Configure API Keys
  $ cp .env.example .env
  $ nano .env  # or your preferred editor
  
  Add your API keys:
    - GEMINI_API_KEY (required)
    - OPENAI_API_KEY (optional, recommended)
    - SHODAN_API_KEY (required)
    - CENSYS_API_ID and CENSYS_API_SECRET (required)
    - ABUSEIPDB_API_KEY (optional)
    - PROJECTHONEYPOT_API_KEY (optional)
    - GREYNOISE_API_KEY (optional)

Step 4: Verify Installation
  $ nmap --version
  $ python osint_llm.py

2. YOUR FIRST SCAN (10 minutes)
-------------------------------

Option A: Simple OSINT Only
  $ python osint_llm.py
  1. Select Option 1 (Standard OSINT Scan)
  2. Enter target: 8.8.8.8
  3. Wait for results
  4. Check output files:
     - osint_scan_8.8.8.8_[timestamp].json
     - osint_scan_8.8.8.8_[timestamp].md

Option B: OSINT + NMap
  $ python osint_llm.py
  1. Select Option 2 (OSINT Scan + NMap)
  2. Enter target: 8.8.8.8
  3. Select NMap profile: 1 (Quick Scan - fastest)
  4. Wait for results
  5. Check output files with full NMap data

Option C: View Available Options
  $ python osint_llm.py
  1. Select Option 3 (View NMap Profiles)
  2. Select Option 4 (View NMap Switches)
  3. Review before choosing custom scan arguments

3. UNDERSTANDING YOUR RESULTS
-----------------------------

JSON Output (osint_scan_[target]_[timestamp].json)
  - Structured data for parsing
  - Includes all OSINT sources
  - Contains raw NMap results
  - Good for integration with other tools

Markdown Output (osint_scan_[target]_[timestamp].md)
  - Human-readable report
  - LLM analysis and recommendations
  - Organized by source
  - Ready for sharing with teams

Key Sections in Results:
  1. Target Information - Who/what was scanned
  2. IP Information - Geolocation and ASN data
  3. Shodan Results - Known open ports and services
  4. Censys Results - Certificate and protocol information
  5. SSL Certificate - HTTPS certificate details
  6. DNS Records - Domain resolution records
  7. WHOIS Information - Domain registration data
  8. Threat Intelligence - Reputation and abuse history
  9. NMap Results - Detailed port scanning data
  10. LLM Analysis - AI-powered security assessment

4. NMap SCANNING PROFILES EXPLAINED
-----------------------------------

Quick Scan (Recommended for beginners)
  - Scans top 100 ports only
  - Takes 1-2 minutes
  - Good for initial reconnaissance
  - Use when: You just want to know if services are running

Comprehensive Scan
  - Scans all 65,535 ports
  - Includes service version detection
  - Includes OS detection
  - Takes 5-15 minutes
  - Use when: You need detailed port/service information

Vulnerability Scan
  - Uses vulnerability detection scripts
  - Checks for known CVEs
  - Takes 10-20 minutes
  - Use when: Checking for known vulnerabilities

Aggressive Scan
  - Maximum detection and timing
  - Includes all options above
  - Takes 15-30 minutes
  - Use when: You need everything and have time

Custom Arguments
  - For advanced users
  - Full NMap command syntax supported
  - Examples:
    -p 80,443,22 -sV          (specific ports, version detection)
    -p 1-1000 -T4 -A          (first 1000 ports, aggressive)
    -Pn -p 445 -sC            (skip ping, SMB, default scripts)

5. COMMON SCANNING SCENARIOS
----------------------------

Scenario 1: Quick Server Assessment
  Profile: Quick Scan
  Time: 2 minutes
  Results: Open ports, basic service info
  Command: -F --top-ports 100

Scenario 2: Detailed Port Analysis
  Profile: Comprehensive Scan
  Time: 10 minutes
  Results: All ports, services, OS, scripts
  Command: -p- -sV -sC -O --osscan-guess

Scenario 3: Vulnerability Discovery
  Profile: Vulnerability Scan
  Time: 15 minutes
  Results: Known CVEs, weak configurations
  Command: -sV --script vuln -p- --script-args unsafe=1

Scenario 4: Domain Reconnaissance
  Target: google.com
  Profile: Quick Scan
  Time: 5 minutes
  Results: IP address, open ports, services
  Note: DNS resolution happens automatically

Scenario 5: Network Segment Assessment
  Target: 192.168.1.0/24
  Profile: Quick Scan (modify to use -p 22,80,443)
  Time: Varies by number of hosts
  Results: Hosts up, services per host

6. THREAT INTELLIGENCE SOURCES
------------------------------

Included Sources:
  ✓ IPInfo - Geolocation and ISP data
  ✓ Shodan - Internet-facing service database
  ✓ Censys - Certificate and protocol data
  ✓ VirusTotal - Malware and file analysis (optional)
  ✓ AbuseIPDB - IP reputation and abuse reports
  ✓ Project Honeypot - Honeypot threat data
  ✓ GreyNoise - IP classification and threat tags

What You'll Find:
  - Where the server is located (country, city, ISP)
  - What ports and services are running
  - What SSL certificates are installed
  - Domain registration information
  - Known security incidents
  - Threat classifications
  - Abuse complaints
  - Honeypot interactions

7. LLM ANALYSIS FEATURES
------------------------

The tool automatically analyzes all data and provides:

1. Summary of Findings
   - What was discovered about the target
   - Key characteristics identified

2. Security Concerns
   - Vulnerabilities detected
   - Weak configurations
   - Exposed services
   - Suspicious activity

3. Risk Assessment
   - Overall risk level
   - Specific risk factors
   - Context-based assessment

4. Remediation Recommendations
   - How to fix identified issues
   - Best practices to implement
   - Security hardening steps

5. Additional Investigation Areas
   - What to look into further
   - Potential attack vectors
   - Related systems to check

8. BEST PRACTICES
-----------------

For Responsible Scanning:
  ✓ Only scan systems you own or have permission for
  ✓ Start with Quick Scan before aggressive scans
  ✓ Respect API rate limits of services
  ✓ Keep API keys in .env file (never commit)
  ✓ Review results for false positives
  ✓ Use appropriate timing profiles (-T0 to -T5)

For Security:
  ✓ Store .env file securely (chmod 600)
  ✓ Use unique API keys for each tool
  ✓ Rotate API keys periodically
  ✓ Monitor API usage and costs
  ✓ Document your scan results
  ✓ Share reports securely

For Efficiency:
  ✓ Use Quick Scan for initial assessment
  ✓ Use Comprehensive only when needed
  ✓ Schedule long scans during off-hours
  ✓ Batch multiple targets together
  ✓ Use custom arguments for specific needs

9. TROUBLESHOOTING
------------------

Problem: "NMap is not installed"
Solution:
  Follow installation steps in section 1
  Verify: nmap --version

Problem: "API key not configured"
Solution:
  Check .env file has all required keys
  Run: python config.py
  Add missing keys and try again

Problem: "Permission denied" for OS detection
Solution:
  Use: sudo python osint_llm.py
  OR use profile without -O flag (not Comprehensive)
  OR use custom args without OS detection

Problem: Scans are timing out
Solution:
  Increase TIMEOUT in .env (default 30 seconds)
  Use Quick Scan instead of Comprehensive
  Check network connectivity

Problem: Rate limiting errors
Solution:
  Increase REQUEST_DELAY in .env
  Reduce number of targets
  Wait before scanning same target again

Problem: Poor LLM analysis
Solution:
  Ensure API key is valid and has credits
  Check that target has detected data
  Try alternative LLM (OpenAI vs Gemini)

10. NEXT STEPS
---------------

After First Scan:
  1. Review the markdown report
  2. Check the LLM analysis section
  3. Understand the recommendations
  4. Scan additional targets with same profile
  5. Explore different scanning profiles

Advanced Usage:
  1. Study NMap documentation: https://nmap.org/
  2. Learn custom NSE scripts: https://nmap.org/nsedoc/
  3. Combine with other security tools
  4. Automate scanning with cron jobs
  5. Parse JSON output in your tools

Team Usage:
  1. Share markdown reports with stakeholders
  2. Export JSON for processing
  3. Set up scheduled scans
  4. Create dashboards for results
  5. Integrate with security platforms

11. USEFUL COMMANDS
-------------------

Check NMap version and features:
  $ nmap --version

View this guide:
  $ cat NMAP_INTEGRATION_README.md

Test configuration:
  $ python config.py

Run with specific target:
  $ echo "192.168.1.1" | python osint_llm.py

View JSON results:
  $ python -m json.tool osint_scan_*.json

Search results:
  $ grep -i "port" osint_scan_*.md

12. EXAMPLE WORKFLOW
--------------------

Basic OSINT Investigation:
  $ python osint_llm.py
  >> Option 1: Standard OSINT
  >> Target: suspicious.com
  >> Results: IP, services, threat data
  >> Output: Check markdown report

Network Reconnaissance:
  $ python osint_llm.py
  >> Option 2: OSINT + NMap
  >> Target: target.com
  >> NMap Profile: 2 (Comprehensive)
  >> Results: Full network map + LLM analysis

Multi-Target Assessment:
  $ python osint_llm.py
  >> Option 2: OSINT + NMap
  >> Target 1: 192.168.1.1
  >> Target 2: 192.168.1.2
  >> Target 3: 192.168.1.3
  >> NMap Profile: 1 (Quick)
  >> Results: Three reports with comparative analysis

13. EXAMPLE OUTPUT SNIPPETS
---------------------------

Quick Scan NMap Output Section:
  ┌─────────────────────────────────┐
  │ NMap Results                    │
  │ ─────────────────────────────   │
  │ Hosts Scanned: 1                │
  │ Hosts Up: 1                     │
  │ Open Ports Found: 3             │
  │                                 │
  │ Open Ports:                     │
  │   22/tcp  open    ssh           │
  │   80/tcp  open    http          │
  │   443/tcp open    https         │
  └─────────────────────────────────┘

LLM Analysis Snippet:
  ┌─────────────────────────────────┐
  │ LLM Analysis Summary            │
  │ ─────────────────────────────   │
  │ ## Security Concerns            │
  │ - SSH exposed to public         │
  │ - No WAF detected               │
  │ - Outdated service version      │
  │                                 │
  │ ## Risk Level: MEDIUM           │
  │ ## Recommendations:             │
  │ - Restrict SSH to whitelist IPs │
  │ - Update services to latest     │
  │ - Implement WAF rules           │
  └─────────────────────────────────┘

14. GETTING HELP
-----------------

Documentation:
  - NMAP_INTEGRATION_README.md - Full feature documentation
  - README.md - Main project documentation
  - .env.example - API key setup guide

External Resources:
  - NMap Official Guide: https://nmap.org/book/
  - OWASP Scanning Guide: https://owasp.org/
  - Shodan Docs: https://shodan.io/
  - GitHub Issues: Report bugs or request features

Tips:
  - Start with Quick Scan profile
  - Review markdown output first (easier to read)
  - Check JSON for detailed data
  - Refer to NMap switches guide for custom args

15. SECURITY REMINDERS
----------------------

⚠️  IMPORTANT:
  - Never scan systems without authorization
  - Keep your .env file private (add to .gitignore)
  - Use strong, unique API keys
  - Monitor your API usage and costs
  - Some scans may trigger IDS/IPS systems
  - Verify you have proper testing permissions
  - Review laws in your jurisdiction

✓ GOOD PRACTICES:
  - Document what you scan and when
  - Use separate API keys for dev and prod
  - Rotate credentials regularly
  - Share results securely
  - Keep software up to date
  - Test on authorized systems only

Ready to start? Run:
  $ python osint_llm.py

Happy scanning! 🔍
"""

# Quick reference constants
QUICK_START_TARGETS = {
    "public_dns": "8.8.8.8",
    "google": "google.com",
    "cloudflare": "1.1.1.1",
    "github": "github.com"
}

NMAP_PROFILES_QUICK_REF = {
    "1": ("Quick", "1-2 min", "Common ports only"),
    "2": ("Comprehensive", "5-15 min", "All ports + services"),
    "3": ("Vulnerability", "10-20 min", "CVE detection"),
    "4": ("Aggressive", "15-30 min", "Everything"),
}

if __name__ == "__main__":
    print(__doc__)
    print("\nQuick Reference - Sample Targets:")
    for name, ip in QUICK_START_TARGETS.items():
        print(f"  {name:20s} {ip}")
    
    print("\nQuick Reference - NMap Profiles:")
    for key, (name, time, desc) in NMAP_PROFILES_QUICK_REF.items():
        print(f"  {key}: {name:20s} ({time:10s}) - {desc}")
