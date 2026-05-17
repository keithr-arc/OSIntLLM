"""
OSIntLLM - Open Source Intelligence with Large Language Models
Integrates Google Gemini, OpenAI, IPInfo, Shodan, Censys, NMap, and other OSINT sources
Python 3.10+
"""

import asyncio
import json
import re
import ssl
import socket
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from urllib.parse import urlparse
import warnings

# Third-party imports
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import google.generativeai as genai
from ipaddress import ip_address, AddressValueError

# Local imports
from config import APIConfig, validate_config
from nmap_integration import NMapScanner, NMapResult

warnings.filterwarnings('ignore', message='Unverified HTTPS request')


@dataclass
class OSIntResult:
    """Data class for OSINT results"""
    target: str
    target_type: str  # 'ip', 'domain', 'fqdn', 'url'
    timestamp: str
    ipinfo_data: Dict[str, Any] = None
    shodan_data: Dict[str, Any] = None
    censys_data: Dict[str, Any] = None
    ssl_certificate: Dict[str, Any] = None
    whois_data: Dict[str, Any] = None
    dns_records: Dict[str, Any] = None
    ports_open: List[int] = None
    vulnerabilities: List[Dict[str, Any]] = None
    threat_intelligence: Dict[str, Any] = None
    nmap_results: NMapResult = None
    llm_analysis: str = None
    summary: str = None

    def to_json(self) -> str:
        """Convert result to JSON"""
        return json.dumps(asdict(self), indent=2, default=str)


class OSIntLLM:
    """Main OSINT and LLM integration class"""
    
    def __init__(self, config: APIConfig = None):
        """Initialize OSIntLLM with API configuration"""
        self.config = config or APIConfig()
        self.session = self._create_session()
        self.gemini_model = None
        self.openai_client = None
        self.nmap_scanner = NMapScanner()
        self._init_gemini()
        self._init_openai()
    
    def _create_session(self) -> requests.Session:
        """Create requests session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=self.config.MAX_RETRIES,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def _init_gemini(self) -> None:
        """Initialize Google Gemini API"""
        if not self.config.GEMINI_API_KEY:
            print("Warning: Gemini API key not configured")
            return
        
        try:
            genai.configure(api_key=self.config.GEMINI_API_KEY)
            self.gemini_model = genai.GenerativeModel('gemini-pro')
            print("✓ Gemini API initialized successfully")
        except Exception as e:
            print(f"Error initializing Gemini: {e}")
    
    def _init_openai(self) -> None:
        """Initialize OpenAI API"""
        if not self.config.OPENAI_API_KEY:
            print("Warning: OpenAI API key not configured")
            return
        
        try:
            from openai import OpenAI
            self.openai_client = OpenAI(api_key=self.config.OPENAI_API_KEY)
            print("✓ OpenAI API initialized successfully")
        except Exception as e:
            print(f"Error initializing OpenAI: {e}")
    
    def _normalize_target(self, target: str) -> Tuple[str, str]:
        """
        Normalize and identify target type
        Returns: (normalized_target, target_type)
        """
        target = target.strip().lower()
        
        # Check if it's an IP address
        try:
            ip_address(target)
            return target, "ip"
        except (AddressValueError, ValueError):
            pass
        
        # Check if it's a URL
        if target.startswith(('http://', 'https://', 'ftp://')):
            parsed = urlparse(target)
            return parsed.netloc or target, "url"
        
        # Check if it's a FQDN or domain
        if '.' in target and '/' not in target:
            return target, "fqdn"
        
        return target, "unknown"
    
    def get_ipinfo(self, ip: str) -> Dict[str, Any]:
        """Get IP information from IPInfo.io"""
        if not self.config.IPINFO_API_KEY:
            print("Warning: IPInfo API key not configured")
            return {}
        
        try:
            url = f"https://ipapi.co/{ip}/json/"
            response = self.session.get(url, timeout=self.config.TIMEOUT)
            response.raise_for_status()
            
            data = response.json()
            print(f"✓ IPInfo data retrieved for {ip}")
            return {
                "ip": data.get("ip"),
                "organization": data.get("org"),
                "isp": data.get("org_name"),
                "country": data.get("country_name"),
                "region": data.get("region"),
                "city": data.get("city"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "asn": data.get("asn"),
                "timezone": data.get("timezone"),
            }
        except Exception as e:
            print(f"Error fetching IPInfo data: {e}")
            return {}
    
    def get_shodan_info(self, target: str) -> Dict[str, Any]:
        """Get Shodan information for IP or hostname"""
        if not self.config.SHODAN_API_KEY:
            print("Warning: Shodan API key not configured")
            return {}
        
        try:
            # First, get IP address if target is hostname
            ip = target
            target_type = self._normalize_target(target)[1]
            
            if target_type != "ip":
                try:
                    ip = socket.gethostbyname(target)
                except socket.gaierror:
                    print(f"Could not resolve {target} to IP address")
                    return {}
            
            url = f"https://api.shodan.io/shodan/host/{ip}"
            params = {"key": self.config.SHODAN_API_KEY}
            response = self.session.get(url, params=params, timeout=self.config.TIMEOUT)
            response.raise_for_status()
            
            data = response.json()
            print(f"✓ Shodan data retrieved for {ip}")
            
            return {
                "ip": data.get("ip_str"),
                "organization": data.get("org"),
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "services": [
                    {
                        "port": item.get("port"),
                        "protocol": item.get("_shodan", {}).get("module"),
                        "data": item.get("data"),
                        "timestamp": item.get("timestamp"),
                    }
                    for item in data.get("data", [])
                ],
                "last_update": data.get("last_update"),
                "vulns": data.get("vulns", []),
            }
        except Exception as e:
            print(f"Error fetching Shodan data: {e}")
            return {}
    
    def get_censys_info(self, ip: str) -> Dict[str, Any]:
        """Get Censys information for IP"""
        if not self.config.CENSYS_API_ID or not self.config.CENSYS_API_SECRET:
            print("Warning: Censys API credentials not configured")
            return {}
        
        try:
            url = f"https://api.censys.io/api/v1/ipv4/{ip}"
            auth = (self.config.CENSYS_API_ID, self.config.CENSYS_API_SECRET)
            response = self.session.get(url, auth=auth, timeout=self.config.TIMEOUT)
            response.raise_for_status()
            
            data = response.json()
            print(f"✓ Censys data retrieved for {ip}")
            
            return {
                "ip": ip,
                "protocols": data.get("protocols", []),
                "autonomous_system": data.get("autonomous_system", {}),
                "last_updated": data.get("last_updated"),
                "services": [
                    {
                        "port": item.get("port"),
                        "protocol": item.get("service", {}).get("name"),
                    }
                    for item in data.get("services", [])
                ],
            }
        except Exception as e:
            print(f"Error fetching Censys data: {e}")
            return {}
    
    def get_ssl_certificate(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=self.config.TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    print(f"✓ SSL certificate retrieved for {hostname}")
                    
                    return {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "version": cert.get("version"),
                        "serial_number": cert.get("serialNumber"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "subjectAltName": [x[1] for x in cert.get("subjectAltName", [])],
                    }
        except Exception as e:
            print(f"Error retrieving SSL certificate: {e}")
            return {}
    
    def get_dns_records(self, hostname: str) -> Dict[str, Any]:
        """Get DNS records for hostname"""
        try:
            import dns.resolver
            
            records = {
                "A": [],
                "AAAA": [],
                "MX": [],
                "NS": [],
                "TXT": [],
                "CNAME": [],
            }
            
            for record_type in records.keys():
                try:
                    answers = dns.resolver.resolve(hostname, record_type)
                    records[record_type] = [str(rdata) for rdata in answers]
                except Exception:
                    pass
            
            print(f"✓ DNS records retrieved for {hostname}")
            return records
        except ImportError:
            print("Warning: dnspython not installed. Skipping DNS lookups")
            return {}
        except Exception as e:
            print(f"Error retrieving DNS records: {e}")
            return {}
    
    def get_whois_info(self, target: str) -> Dict[str, Any]:
        """Get WHOIS information"""
        try:
            import whois
            
            whois_data = whois.whois(target)
            print(f"✓ WHOIS data retrieved for {target}")
            
            return {
                "registrar": str(whois_data.registrar) if whois_data.registrar else None,
                "creation_date": str(whois_data.creation_date) if whois_data.creation_date else None,
                "expiration_date": str(whois_data.expiration_date) if whois_data.expiration_date else None,
                "updated_date": str(whois_data.updated_date) if whois_data.updated_date else None,
                "name_servers": whois_data.name_servers if whois_data.name_servers else [],
                "registrant_name": str(whois_data.registrant_name) if hasattr(whois_data, 'registrant_name') else None,
            }
        except ImportError:
            print("Warning: whois not installed. Skipping WHOIS lookups")
            return {}
        except Exception as e:
            print(f"Error retrieving WHOIS data: {e}")
            return {}
    
    def get_threat_intelligence(self, target: str) -> Dict[str, Any]:
        """Get threat intelligence from multiple sources"""
        threat_data = {}
        
        # VirusTotal
        if self.config.VIRUSTOTAL_API_KEY:
            threat_data["virustotal"] = self._query_virustotal(target)
        
        # AbuseIPDB
        if self.config.ABUSEIPDB_API_KEY:
            threat_data["abuseipdb"] = self._query_abuseipdb(target)
        
        # Project Honeypot
        if self.config.PROJECTHONEYPOT_API_KEY:
            threat_data["projecthoneypot"] = self._query_projecthoneypot(target)
        
        # GreyNoise
        if self.config.GREYNOISE_API_KEY:
            threat_data["greynoise"] = self._query_greynoise(target)
        
        return threat_data
    
    def _query_virustotal(self, target: str) -> Dict[str, Any]:
        """Query VirusTotal API"""
        try:
            url = "https://www.virustotal.com/api/v3/search"
            headers = {"x-apikey": self.config.VIRUSTOTAL_API_KEY}
            params = {"query": target}
            response = self.session.get(url, headers=headers, params=params, timeout=self.config.TIMEOUT)
            response.raise_for_status()
            
            data = response.json()
            print(f"✓ VirusTotal data retrieved for {target}")
            return data.get("data", {})
        except Exception as e:
            print(f"Error querying VirusTotal: {e}")
            return {}
    
    def _query_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB API"""
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self.config.ABUSEIPDB_API_KEY, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
            response = self.session.get(url, headers=headers, params=params, timeout=self.config.TIMEOUT)
            response.raise_for_status()
            
            data = response.json()
            print(f"✓ AbuseIPDB data retrieved for {ip}")
            return data.get("data", {})
        except Exception as e:
            print(f"Error querying AbuseIPDB: {e}")
            return {}
    
    def _query_projecthoneypot(self, ip: str) -> Dict[str, Any]:
        """Query Project Honeypot API"""
        try:
            url = f"https://www.projecthoneypot.org/api/v1/{self.config.PROJECTHONEYPOT_API_KEY}/ip/{ip}"
            response = self.session.get(url, timeout=self.config.TIMEOUT)
            response.raise_for_status()
            
            data = response.json()
            print(f"✓ Project Honeypot data retrieved for {ip}")
            return {
                "threat_level": data.get("threat_level"),
                "threat_type": data.get("threat_type"),
                "last_seen": data.get("last_seen"),
                "activity": data.get("activity")
            }
        except Exception as e:
            print(f"Error querying Project Honeypot: {e}")
            return {}
    
    def _query_greynoise(self, ip: str) -> Dict[str, Any]:
        """Query GreyNoise API"""
        try:
            url = f"https://api.greynoise.io/v3/community/{ip}"
            headers = {"key": self.config.GREYNOISE_API_KEY}
            response = self.session.get(url, headers=headers, timeout=self.config.TIMEOUT)
            response.raise_for_status()
            
            data = response.json()
            print(f"✓ GreyNoise data retrieved for {ip}")
            return {
                "classification": data.get("classification"),
                "last_seen": data.get("last_seen"),
                "seen": data.get("seen"),
                "tags": data.get("tags", []),
                "actions": data.get("actions", [])
            }
        except Exception as e:
            print(f"Error querying GreyNoise: {e}")
            return {}
    
    def analyze_with_gemini(self, osint_data: Dict[str, Any]) -> str:
        """Analyze OSINT data with Google Gemini"""
        if not self.gemini_model:
            print("Warning: Gemini not initialized")
            return ""
        
        try:
            prompt = f"""
You are a cybersecurity expert analyzing Open Source Intelligence (OSINT) data.
Please analyze the following OSINT data and provide:
1. Summary of findings
2. Security concerns and vulnerabilities identified
3. Risk assessment
4. Recommendations for remediation
5. Additional areas to investigate

OSINT Data:
{json.dumps(osint_data, indent=2, default=str)}

Provide a detailed, professional analysis in markdown format.
"""
            response = self.gemini_model.generate_content(prompt)
            print("✓ Gemini analysis completed")
            return response.text
        except Exception as e:
            print(f"Error analyzing with Gemini: {e}")
            return ""
    
    def analyze_with_openai(self, osint_data: Dict[str, Any]) -> str:
        """Analyze OSINT data with OpenAI ChatGPT"""
        if not self.openai_client:
            print("Warning: OpenAI not initialized")
            return ""
        
        try:
            prompt = f"""
You are a cybersecurity expert analyzing Open Source Intelligence (OSINT) data.
Please analyze the following OSINT data and provide:
1. Summary of findings
2. Security concerns and vulnerabilities identified
3. Risk assessment
4. Recommendations for remediation
5. Additional areas to investigate

OSINT Data:
{json.dumps(osint_data, indent=2, default=str)}

Provide a detailed, professional analysis in markdown format.
"""
            response = self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing OSINT data."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=2000
            )
            print("✓ OpenAI analysis completed")
            return response.choices[0].message.content
        except Exception as e:
            print(f"Error analyzing with OpenAI: {e}")
            return ""
    
    def perform_nmap_scan(self, target: str, profile: str = "quick", custom_args: str = None) -> NMapResult:
        """
        Perform NMap scan on target
        
        Args:
            target: IP address or FQDN to scan
            profile: Preset profile ('quick', 'comprehensive', 'vulnerability', 'aggressive')
            custom_args: Custom NMap arguments to override profile
        
        Returns:
            NMapResult object with scan results
        """
        try:
            result = self.nmap_scanner.scan(target, profile, custom_args)
            return result
        except Exception as e:
            print(f"Error performing NMap scan: {e}")
            return None
    
    def scan(self, target: str, run_nmap: bool = False, nmap_profile: str = "quick") -> OSIntResult:
        """
        Perform comprehensive OSINT scan on target
        Target can be: IP address, FQDN, domain, or URL
        """
        normalized_target, target_type = self._normalize_target(target)
        
        print(f"\n{'='*60}")
        print(f"Scanning: {target}")
        print(f"Type: {target_type}")
        print(f"{'='*60}\n")
        
        result = OSIntResult(
            target=target,
            target_type=target_type,
            timestamp=datetime.now().isoformat(),
        )
        
        # Resolve to IP if needed
        ip = normalized_target
        if target_type in ["fqdn", "url"]:
            try:
                ip = socket.gethostbyname(normalized_target)
                print(f"Resolved {normalized_target} to {ip}")
            except socket.gaierror:
                print(f"Could not resolve {normalized_target}")
                ip = None
        
        # Gather OSINT data
        print("\n[1/8] Fetching IPInfo data...")
        if ip:
            result.ipinfo_data = self.get_ipinfo(ip)
            time.sleep(self.config.REQUEST_DELAY)
        
        print("[2/8] Fetching Shodan data...")
        if ip:
            result.shodan_data = self.get_shodan_data(ip)
            result.ports_open = result.shodan_data.get("ports", [])
            time.sleep(self.config.REQUEST_DELAY)
        
        print("[3/8] Fetching Censys data...")
        if ip:
            result.censys_data = self.get_censys_info(ip)
            time.sleep(self.config.REQUEST_DELAY)
        
        print("[4/8] Fetching SSL certificate...")
        if target_type in ["fqdn", "url"]:
            result.ssl_certificate = self.get_ssl_certificate(normalized_target)
            time.sleep(self.config.REQUEST_DELAY)
        
        print("[5/8] Fetching DNS records...")
        if target_type in ["fqdn", "url"]:
            result.dns_records = self.get_dns_records(normalized_target)
            time.sleep(self.config.REQUEST_DELAY)
        
        print("[6/8] Fetching WHOIS data...")
        result.whois_data = self.get_whois_info(normalized_target)
        time.sleep(self.config.REQUEST_DELAY)
        
        print("[7/8] Fetching threat intelligence...")
        if ip:
            result.threat_intelligence = self.get_threat_intelligence(ip)
            time.sleep(self.config.REQUEST_DELAY)
        
        # NMap scan (optional)
        if run_nmap:
            print("[8/8] Performing NMap scan...")
            if ip:
                result.nmap_results = self.perform_nmap_scan(ip, nmap_profile)
                time.sleep(self.config.REQUEST_DELAY)
        
        # Analyze with LLM
        print("\n[LLM] Analyzing findings with LLMs...")
        osint_summary = {
            "ipinfo": result.ipinfo_data,
            "shodan": result.shodan_data,
            "censys": result.censys_data,
            "ssl_certificate": result.ssl_certificate,
            "dns_records": result.dns_records,
            "whois": result.whois_data,
            "threat_intelligence": result.threat_intelligence,
            "nmap": asdict(result.nmap_results) if result.nmap_results else None,
        }
        
        # Try OpenAI first, fall back to Gemini
        if self.openai_client:
            result.llm_analysis = self.analyze_with_openai(osint_summary)
        else:
            result.llm_analysis = self.analyze_with_gemini(osint_summary)
        
        # Generate summary
        result.summary = self._generate_summary(result)
        
        return result
    
    def get_shodan_data(self, ip: str) -> Dict[str, Any]:
        """Wrapper for get_shodan_info for consistency"""
        return self.get_shodan_info(ip)
    
    def _generate_summary(self, result: OSIntResult) -> str:
        """Generate a text summary of results"""
        nmap_info = ""
        if result.nmap_results:
            nmap_info = f"\n- NMap Scan: {result.nmap_results.hosts_up} hosts up, {len(result.nmap_results.open_ports)} open ports"
        
        summary = f"""
OSINT Scan Summary
==================
Target: {result.target}
Type: {result.target_type}
Timestamp: {result.timestamp}

Key Findings:
- Open Ports: {result.ports_open if result.ports_open else 'None detected'}
- SSL Certificate: {'Valid' if result.ssl_certificate else 'Not found'}
- DNS Records: {len(result.dns_records) if result.dns_records else 0} records
- Threat Indicators: {'Found' if result.threat_intelligence else 'None'}{nmap_info}

For detailed analysis, see LLM analysis section.
"""
        return summary
    
    def export_results(self, result: OSIntResult, format: str = "json", filename: str = None) -> str:
        """Export results in various formats"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"osint_scan_{result.target}_{timestamp}"
        
        if format.lower() == "json":
            content = result.to_json()
            filename = f"{filename}.json"
        elif format.lower() == "markdown":
            content = self._format_markdown(result)
            filename = f"{filename}.md"
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        try:
            with open(filename, 'w') as f:
                f.write(content)
            print(f"✓ Results exported to {filename}")
            return filename
        except Exception as e:
            print(f"Error exporting results: {e}")
            return ""
    
    def _format_markdown(self, result: OSIntResult) -> str:
        """Format results as markdown"""
        nmap_section = ""
        if result.nmap_results:
            nmap_section = f"""
## NMap Results
{self.nmap_scanner.format_results(result.nmap_results)}
"""
        
        md = f"""# OSINT Scan Report

## Target Information
- **Target:** {result.target}
- **Type:** {result.target_type}
- **Scan Date:** {result.timestamp}

## IP Information
{self._dict_to_md(result.ipinfo_data) if result.ipinfo_data else 'No data'}

## Shodan Results
{self._dict_to_md(result.shodan_data) if result.shodan_data else 'No data'}

## Censys Results
{self._dict_to_md(result.censys_data) if result.censys_data else 'No data'}

## SSL Certificate
{self._dict_to_md(result.ssl_certificate) if result.ssl_certificate else 'No data'}

## DNS Records
{self._dict_to_md(result.dns_records) if result.dns_records else 'No data'}

## WHOIS Information
{self._dict_to_md(result.whois_data) if result.whois_data else 'No data'}

## Threat Intelligence
{self._dict_to_md(result.threat_intelligence) if result.threat_intelligence else 'No data'}

{nmap_section}

## LLM Analysis
{result.llm_analysis if result.llm_analysis else 'No analysis available'}

## Summary
{result.summary}
"""
        return md
    
    @staticmethod
    def _dict_to_md(data: Dict[str, Any], level: int = 3) -> str:
        """Convert dictionary to markdown"""
        if not data:
            return "No data"
        
        md = ""
        for key, value in data.items():
            if isinstance(value, dict):
                md += f"{'#' * level} {key}\n{OSIntLLM._dict_to_md(value, level + 1)}\n"
            elif isinstance(value, list):
                md += f"- **{key}:** {', '.join(str(v) for v in value)}\n"
            else:
                md += f"- **{key}:** {value}\n"
        
        return md


def display_menu() -> str:
    """Display main menu and get user choice"""
    print("\n" + "="*60)
    print("OSIntLLM - Open Source Intelligence with LLM Analysis")
    print("="*60)
    print("\n1. Standard OSINT Scan")
    print("2. OSINT Scan + NMap")
    print("3. View NMap Profiles")
    print("4. View NMap Switches")
    print("5. Exit")
    print("="*60)
    return input("\nSelect option (1-5): ").strip()


def main():
    """Main function"""
    print("OSIntLLM - Open Source Intelligence with LLM Analysis")
    print("=" * 60)
    
    # Validate configuration
    if not validate_config():
        print("\nPlease configure your API keys in .env file")
        return
    
    # Initialize OSIntLLM
    config = APIConfig()
    osint_llm = OSIntLLM(config)
    
    while True:
        choice = display_menu()
        
        if choice == "5":
            print("Exiting...")
            break
        
        elif choice == "3":
            # Display NMap profiles
            print("\nAvailable NMap Profiles:")
            print("="*60)
            profiles = osint_llm.nmap_scanner.get_available_profiles()
            for profile_key, profile_info in profiles.items():
                print(f"\n{profile_key.upper()}:")
                print(f"  Name: {profile_info['name']}")
                print(f"  Description: {profile_info['description']}")
                print(f"  Estimated Time: {profile_info['time_estimate']}")
        
        elif choice == "4":
            # Display NMap switches
            print("\nAvailable NMap Switches:")
            print("="*60)
            switches = osint_llm.nmap_scanner.get_nmap_switches()
            for switch, description in switches.items():
                print(f"{switch:25s} - {description}")
        
        elif choice == "1" or choice == "2":
            # Get target
            print("\nEnter targets to scan (one per line, empty line to finish):")
            print("Examples: 8.8.8.8, google.com, https://example.com\n")
            
            targets = []
            while True:
                target = input("Target: ").strip()
                if not target:
                    break
                targets.append(target)
            
            if not targets:
                print("No targets provided. Returning to menu.")
                continue
            
            # Get NMap options if choice is 2
            run_nmap = (choice == "2")
            nmap_profile = "quick"
            custom_nmap_args = None
            
            if run_nmap:
                print("\nNMap Scanning Options:")
                print("1. Quick Scan (default)")
                print("2. Comprehensive Scan")
                print("3. Vulnerability Scan")
                print("4. Aggressive Scan")
                print("5. Custom Arguments")
                nmap_choice = input("\nSelect NMap profile (1-5, default=1): ").strip()
                
                if nmap_choice == "2":
                    nmap_profile = "comprehensive"
                elif nmap_choice == "3":
                    nmap_profile = "vulnerability"
                elif nmap_choice == "4":
                    nmap_profile = "aggressive"
                elif nmap_choice == "5":
                    custom_nmap_args = input("Enter custom NMap arguments: ").strip()
                
                if not osint_llm.nmap_scanner.nmap_available:
                    print("Warning: NMap is not installed. Proceeding with standard OSINT scan only.")
                    run_nmap = False
            
            # Scan targets
            results = []
            for target in targets:
                try:
                    result = osint_llm.scan(target, run_nmap=run_nmap, nmap_profile=nmap_profile)
                    results.append(result)
                    
                    # Print summary
                    print(f"\n{result.summary}")
                    
                    # Export results
                    osint_llm.export_results(result, format="json")
                    osint_llm.export_results(result, format="markdown")
                    
                except Exception as e:
                    print(f"Error scanning {target}: {e}")
                    import traceback
                    traceback.print_exc()
            
            print("\n" + "=" * 60)
            print(f"Scan completed for {len(results)} target(s)")
            print("=" * 60)


if __name__ == "__main__":
    main()
