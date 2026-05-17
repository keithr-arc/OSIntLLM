"""
NMap Integration Module for OSIntLLM
Provides network scanning capabilities with preset profiles and custom options
"""

import subprocess
import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import socket
from ipaddress import ip_address, AddressValueError


@dataclass
class NMapResult:
    """Data class for NMap scan results"""
    target: str
    scan_type: str  # 'quick', 'comprehensive', 'vulnerability', 'custom'
    timestamp: str
    command_used: str
    hosts_scanned: int
    hosts_up: int
    open_ports: List[Dict[str, Any]] = None
    services_detected: List[Dict[str, Any]] = None
    os_detection: Dict[str, Any] = None
    vulnerabilities: List[Dict[str, Any]] = None
    raw_output: str = None
    
    def to_json(self) -> str:
        """Convert result to JSON"""
        return json.dumps(asdict(self), indent=2, default=str)


class NMapScanner:
    """NMap network scanner with preset profiles"""
    
    # Preset scanning profiles
    SCAN_PROFILES = {
        "quick": {
            "name": "Quick Scan",
            "description": "Fast scan of common ports only",
            "args": "-F --top-ports 100",
            "time_estimate": "1-2 minutes"
        },
        "comprehensive": {
            "name": "Comprehensive Scan",
            "description": "Scan all ports with service and version detection",
            "args": "-p- -sV -sC -O --osscan-guess",
            "time_estimate": "5-15 minutes"
        },
        "vulnerability": {
            "name": "Vulnerability Scan",
            "description": "Scan for vulnerabilities using NSE scripts",
            "args": "-sV --script vuln -p- --script-args unsafe=1",
            "time_estimate": "10-20 minutes"
        },
        "aggressive": {
            "name": "Aggressive Scan",
            "description": "Aggressive scan with all detection and timing",
            "args": "-p- -sV -sC -O --osscan-guess -A -T4",
            "time_estimate": "15-30 minutes"
        }
    }
    
    # Available NMap switches documentation
    NMAP_SWITCHES = {
        # Port scanning
        "-p <port ranges>": "Scan specified ports",
        "-F": "Scan 100 most common ports (fast)",
        "-r": "Scan ports consecutively",
        "--top-ports <number>": "Scan top N most common ports",
        
        # Scan types
        "-sS": "TCP SYN stealth scan (requires root)",
        "-sT": "TCP connect scan",
        "-sU": "UDP scan",
        "-sA": "TCP ACK scan",
        "-sW": "TCP Window scan",
        "-sN/-sF/-sX": "TCP Null/FIN/Xmas scan",
        "-sM": "TCP Maimon scan",
        
        # Service detection
        "-sV": "Version detection",
        "-sR": "RPC scan",
        "-O": "OS detection (requires root)",
        "--osscan-guess": "Guess OS if detection fails",
        
        # Scripts
        "-sC": "Run default NSE scripts",
        "--script <name>": "Run specific NSE script",
        "--script vuln": "Scan for vulnerabilities",
        
        # Timing
        "-T0 to -T5": "Timing templates (paranoid to insane)",
        "-T4": "Aggressive timing (default for fast networks)",
        
        # Output
        "-oN <file>": "Normal output to file",
        "-oX <file>": "XML output to file",
        "-oG <file>": "Grepable output to file",
        "-oA <file>": "All formats to file (base name)",
        
        # Host discovery
        "-Pn": "Treat all hosts as online (skip ping)",
        "-PS/PA/PU": "Use TCP SYN/ACK or UDP ping",
        "-PE/PP/PM": "ICMP echo/timestamp/netmask ping",
        "-sL": "List scan (no port scan)",
        
        # Misc
        "-A": "Enable OS detection, version detection, script scanning, traceroute",
        "--traceroute": "Traceroute after port scan",
        "--reason": "Show why port is in that state",
        "--all-ports": "Do not exclude any ports from version detection",
    }
    
    def __init__(self):
        """Initialize NMap scanner"""
        self.nmap_available = self._check_nmap()
    
    def _check_nmap(self) -> bool:
        """Check if NMap is installed"""
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                timeout=5,
                text=True
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def _is_valid_target(self, target: str) -> bool:
        """Validate target is IP or FQDN"""
        # Check if IP address
        try:
            ip_address(target)
            return True
        except (AddressValueError, ValueError):
            pass
        
        # Check if FQDN/domain
        if '.' in target and '/' not in target and len(target) > 2:
            # Basic FQDN validation
            parts = target.split('.')
            if len(parts) >= 2 and all(part.isalnum() or '-' in part for part in parts):
                return True
        
        return False
    
    def get_available_profiles(self) -> Dict[str, Dict[str, str]]:
        """Get available scanning profiles"""
        return {
            k: {
                "name": v["name"],
                "description": v["description"],
                "time_estimate": v["time_estimate"]
            }
            for k, v in self.SCAN_PROFILES.items()
        }
    
    def get_nmap_switches(self) -> Dict[str, str]:
        """Get available NMap switches"""
        return self.NMAP_SWITCHES.copy()
    
    def scan(self, target: str, profile: str = "quick", custom_args: str = None) -> NMapResult:
        """
        Perform NMap scan on target
        
        Args:
            target: IP address or FQDN to scan
            profile: Preset profile ('quick', 'comprehensive', 'vulnerability', 'aggressive')
            custom_args: Custom NMap arguments to override profile
        
        Returns:
            NMapResult object with scan results
        """
        if not self.nmap_available:
            raise RuntimeError("NMap is not installed or not available in PATH")
        
        if not self._is_valid_target(target):
            raise ValueError(f"Invalid target: {target}. Must be valid IP address or FQDN")
        
        # Build command
        if custom_args:
            nmap_args = custom_args
        elif profile in self.SCAN_PROFILES:
            nmap_args = self.SCAN_PROFILES[profile]["args"]
        else:
            raise ValueError(f"Invalid profile: {profile}")
        
        # Construct full command
        cmd = f"nmap {nmap_args} {target}"
        
        print(f"\n{'='*60}")
        print(f"NMap Scan Starting")
        print(f"Target: {target}")
        print(f"Profile: {profile if not custom_args else 'Custom'}")
        print(f"Command: {cmd}")
        print(f"{'='*60}\n")
        
        try:
            # Run NMap with XML output for better parsing
            xml_file = f"nmap_scan_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
            cmd_xml = f"nmap {nmap_args} -oX {xml_file} {target}"
            
            result = subprocess.run(
                cmd_xml,
                shell=True,
                capture_output=True,
                timeout=3600,  # 1 hour timeout
                text=True
            )
            
            if result.returncode not in [0, 1]:  # 0 = success, 1 = no hosts up
                print(f"NMap error: {result.stderr}")
                raise RuntimeError(f"NMap scan failed: {result.stderr}")
            
            # Parse results
            nmap_result = self._parse_nmap_results(target, profile, cmd, xml_file, result.stdout)
            
            print(f"✓ NMap scan completed for {target}")
            return nmap_result
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("NMap scan timed out")
        except Exception as e:
            raise RuntimeError(f"Error running NMap: {str(e)}")
    
    def _parse_nmap_results(self, target: str, profile: str, cmd: str, xml_file: str, raw_output: str) -> NMapResult:
        """Parse NMap XML results"""
        result = NMapResult(
            target=target,
            scan_type=profile,
            timestamp=datetime.now().isoformat(),
            command_used=cmd,
            hosts_scanned=0,
            hosts_up=0,
            open_ports=[],
            services_detected=[],
            os_detection={},
            vulnerabilities=[],
            raw_output=raw_output
        )
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Extract host information
            for host in root.findall("host"):
                result.hosts_scanned += 1
                
                # Check if host is up
                status = host.find("status")
                if status is not None and status.get("state") == "up":
                    result.hosts_up += 1
                
                # Extract ports
                ports = host.find("ports")
                if ports is not None:
                    for port in ports.findall("port"):
                        port_num = port.get("portid")
                        protocol = port.get("protocol")
                        state = port.find("state")
                        service = port.find("service")
                        
                        if state is not None and state.get("state") == "open":
                            port_info = {
                                "port": int(port_num),
                                "protocol": protocol,
                                "state": state.get("state"),
                                "reason": state.get("reason"),
                            }
                            
                            if service is not None:
                                port_info["service"] = service.get("name", "unknown")
                                port_info["product"] = service.get("product", "")
                                port_info["version"] = service.get("version", "")
                                port_info["extrainfo"] = service.get("extrainfo", "")
                            
                            result.open_ports.append(port_info)
                            result.services_detected.append(port_info)
                
                # Extract OS detection
                os_elem = host.find("os")
                if os_elem is not None:
                    for osmatch in os_elem.findall("osmatch"):
                        result.os_detection = {
                            "name": osmatch.get("name"),
                            "accuracy": osmatch.get("accuracy"),
                            "cpe": [cpe.text for cpe in osmatch.findall("cpe")]
                        }
                        break  # Use best match only
        
        except ET.ParseError as e:
            print(f"Warning: Could not parse XML results: {e}")
        except Exception as e:
            print(f"Warning: Error parsing NMap results: {e}")
        
        return result
    
    def format_results(self, result: NMapResult) -> str:
        """Format NMap results as readable text"""
        output = f"""
NMap Scan Results
=================
Target: {result.target}
Scan Type: {result.scan_type}
Timestamp: {result.timestamp}
Command: {result.command_used}

Summary:
--------
Hosts Scanned: {result.hosts_scanned}
Hosts Up: {result.hosts_up}
Open Ports Found: {len(result.open_ports)}

Open Ports:
-----------
"""
        
        if result.open_ports:
            for port in result.open_ports:
                output += f"  {port['port']}/{port['protocol']:4s} {port['state']:10s}"
                if 'service' in port:
                    output += f" {port['service']}"
                    if port.get('version'):
                        output += f" {port['version']}"
                output += "\n"
        else:
            output += "  No open ports detected\n"
        
        if result.os_detection:
            output += f"""
OS Detection:
-------------
OS: {result.os_detection.get('name', 'Unknown')}
Accuracy: {result.os_detection.get('accuracy', 'N/A')}%
"""
        
        output += f"\nFull Command Used:\n{result.command_used}\n"
        
        return output
