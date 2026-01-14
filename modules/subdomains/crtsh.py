#!/usr/bin/env python3
"""
CRT.sh Subdomain Enumeration Module
Uses crt.sh to find subdomains via certificate transparency logs.
"""
import sys
import json
import socket
from datetime import datetime
import urllib.request
import urllib.error
import ssl
import re

def run(target: str) -> dict:
    """
    Enumerate subdomains using CRT.sh.
    
    Args:
        target: Target domain
    
    Returns:
        Dictionary containing discovered subdomains
    """
    result = {
        "module": "subdomains.crtsh",
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "data": []
    }
    
    try:
        # Clean target for CRT.sh query
        domain = target.lstrip('*.')
        
        # CRT.sh query endpoint
        url = f"https://crt.sh/?q={domain}&output=json"
        
        # Create SSL context that doesn't verify certificates for the API call
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        
        with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            subdomains = set()
            for entry in data:
                common_name = entry.get('common_name', '')
                san_names = entry.get('subject_alt_name', '').split(', ') if entry.get('subject_alt_name') else []
                
                # Add common name
                if common_name and common_name != domain:
                    subdomains.add(common_name.lower())
                
                # Add SAN names
                for san in san_names:
                    san = san.strip().lower()
                    if san and san.endswith(domain):
                        subdomains.add(san)
            
            # Filter and sort
            result["data"] = sorted(list(subdomains))
            result["data_count"] = len(result["data"])
            
    except urllib.error.HTTPError as e:
        result["data"] = []
        result["error"] = f"HTTP error: {e.code}"
    except urllib.error.URLError as e:
        result["data"] = []
        result["error"] = f"URL error: {str(e.reason)}"
    except json.JSONDecodeError:
        result["data"] = []
        result["error"] = "Failed to parse CRT.sh response"
    except Exception as e:
        result["data"] = []
        result["error"] = str(e)
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Target required"}, indent=2))
        sys.exit(1)
    
    result = run(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))

