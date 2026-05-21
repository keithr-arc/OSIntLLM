"""
OSIntLLM - Open Source Intelligence with Large Language Models
Integrates Shodan, Censys, GreyNoise, AbuseIPDB, and NMap for IP intelligence
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
    shodan_data: Dict[str, Any] = None
    censys_data: Dict[str, Any] = None
    greynoise_data: Dict[str, Any] = None
    abuseipdb_data: Dict[str, Any] = None
    ports_open: List[int] = None
    nmap_results: NMapResult = None
    summary: str = None

    def to_json(self) -> str:
        """Convert result to JSON"""
        return json.dumps(asdict(self), indent=2, default=str)


class OSIntLLM:
    """Main OSINT integration class for IP intelligence scanning"""
    
    def __init__(self, config: APIConfig = None):
        """Initialize OSIntLLM with API configuration"""
        self.config = config or APIConfig()
        self.session = self._create_session()
        self.nmap_scanner = NMapScanner()
    
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
    
    def get_shodan_info(self, ip: str) -> Dict[str, Any]:
        """Get Shodan information for IP"""
        if not self.config.SHODAN_API_KEY:
            print("Warning: Shodan API key not configured")
            return {}
        
        try:
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
    
    def get_greynoise_info(self, ip: str) -> Dict[str, Any]:
        """Get GreyNoise information for IP"""
        if not self.config.GREYNOISE_API_KEY:
            print("Warning: GreyNoise API key not configured")
            return {}
        
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
    
    def get_abuseipdb_info(self, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB API"""
        if not self.config.ABUSEIPDB_API_KEY:
            print("Warning: AbuseIPDB API key not configured")
            return {}
        
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
        Perform comprehensive OSINT scan on target IP address
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
        print("\n[1/4] Fetching Shodan data...")
        if ip:
            result.shodan_data = self.get_shodan_info(ip)
            result.ports_open = result.shodan_data.get("ports", [])
            time.sleep(self.config.REQUEST_DELAY)
        
        print("[2/4] Fetching Censys data...")
        if ip:
            result.censys_data = self.get_censys_info(ip)
            time.sleep(self.config.REQUEST_DELAY)
        
        print("[3/4] Fetching GreyNoise data...")
        if ip:
            result.greynoise_data = self.get_greynoise_info(ip)
            time.sleep(self.config.REQUEST_DELAY)
        
        print("[4/4] Fetching AbuseIPDB data...")
        if ip:
            result.abuseipdb_data = self.get_abuseipdb_info(ip)
            time.sleep(self.config.REQUEST_DELAY)
        
        # NMap scan (optional)
        if run_nmap:
            print("\n[NMap] Performing NMap scan...")
            if ip:
                result.nmap_results = self.perform_nmap_scan(ip, nmap_profile)
                time.sleep(self.config.REQUEST_DELAY)
        
        # Generate summary
        result.summary = self._generate_summary(result)
        
        return result
    
    def _generate_summary(self, result: OSIntResult) -> str:
        """Generate a text summary of results"""
        nmap_info = ""
        if result.nmap_results:
            nmap_info = f"\n- NMap Scan: {result.nmap_results.hosts_up} hosts up, {len(result.nmap_results.open_ports)} open ports"
        
        summary = f"""
IP Intelligence Scan Summary
=============================
Target: {result.target}
Type: {result.target_type}
Timestamp: {result.timestamp}

Key Findings:
- Open Ports (Shodan): {result.ports_open if result.ports_open else 'None detected'}
- GreyNoise Classification: {result.greynoise_data.get('classification', 'Unknown') if result.greynoise_data else 'No data'}
- AbuseIPDB Score: {result.abuseipdb_data.get('abuseConfidenceScore', 'N/A') if result.abuseipdb_data else 'No data'}{nmap_info}

For detailed analysis, see full JSON/markdown output.
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
        
        md = f"""# IP Intelligence Scan Report

## Target Information
- **Target:** {result.target}
- **Type:** {result.target_type}
- **Scan Date:** {result.timestamp}

## Shodan Results
{self._dict_to_md(result.shodan_data) if result.shodan_data else 'No data'}

## Censys Results
{self._dict_to_md(result.censys_data) if result.censys_data else 'No data'}

## GreyNoise Results
{self._dict_to_md(result.greynoise_data) if result.greynoise_data else 'No data'}

## AbuseIPDB Results
{self._dict_to_md(result.abuseipdb_data) if result.abuseipdb_data else 'No data'}

{nmap_section}

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
    print("OSIntLLM - IP Intelligence Scanner with NMap")
    print("="*60)
    print("\n1. Standard IP Intelligence Scan")
    print("2. IP Intelligence Scan + NMap")
    print("3. View NMap Profiles")
    print("4. View NMap Switches")
    print("5. Exit")
    print("="*60)
    return input("\nSelect option (1-5): ").strip()


def main():
    """Main function"""
    print("OSIntLLM - IP Intelligence Scanner with NMap")
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
            print("\nEnter IP addresses to scan (one per line, empty line to finish):")
            print("Examples: 8.8.8.8, 1.1.1.1, 192.168.1.1\n")
            
            targets = []
            while True:
                target = input("IP Address: ").strip()
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
                    print("Warning: NMap is not installed. Proceeding with standard IP intelligence scan only.")
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
