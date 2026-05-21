"""
Configuration file for OSIntLLM
Store API keys and settings here
"""

import os
from dataclasses import dataclass
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


@dataclass
class APIConfig:
    """API configuration and credentials"""
    
    # Shodan API
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    
    # Censys API
    CENSYS_API_ID: str = os.getenv("CENSYS_API_ID", "")
    CENSYS_API_SECRET: str = os.getenv("CENSYS_API_SECRET", "")
    
    # GreyNoise API
    GREYNOISE_API_KEY: str = os.getenv("GREYNOISE_API_KEY", "")
    
    # AbuseIPDB API
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    
    # Common settings
    TIMEOUT: int = 30
    MAX_RETRIES: int = 3
    REQUEST_DELAY: float = 1.0  # Delay between requests in seconds


def validate_config() -> bool:
    """Validate that required API keys are present"""
    config = APIConfig()
    required_keys = [
        "SHODAN_API_KEY",
        "CENSYS_API_ID",
        "CENSYS_API_SECRET",
        "GREYNOISE_API_KEY",
        "ABUSEIPDB_API_KEY",
    ]
    
    missing_keys = []
    for key in required_keys:
        value = getattr(config, key, "")
        if not value:
            missing_keys.append(key)
    
    if missing_keys:
        print(f"Warning: Missing required API keys: {', '.join(missing_keys)}")
        print("Please set these environment variables in your .env file")
        return False
    
    return True


if __name__ == "__main__":
    config = APIConfig()
    if validate_config():
        print("✓ All required API keys are configured")
    else:
        print("✗ Some API keys are missing")
