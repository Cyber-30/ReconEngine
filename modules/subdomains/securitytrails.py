#!/usr/bin/env python3
"""
SecurityTrails Subdomain Enumeration Module
Uses SecurityTrails API to find subdomains and historical data.
"""
import sys
import json
import socket
from datetime import datetime
import urllib.request
import urllib.error

def run(target: str) -> dict:
    """
    Enumerate subdomains using SecurityTrails.
    
    Args:
        target: Target domain
    
    Returns:
        Dictionary containing subdomain data from SecurityTrails
    """
    result = {
        "module": "subdomains.securitytrails",
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "subdomains": [],
            "history": {}
        }
    }
    
    try:
        domain = target.lstrip('*.')
        
        # SecurityTrails API (free tier)
        # Note: You'll need an API key from securitytrails.com
        api_key = ""  # Add your API key here
        
        if not api_key:
            # Return sample data structure with note
            result["data"]["note"] = "SecurityTrails API key required. Set API key in config/api_keys.yaml"
            result["data"]["subdomains"] = []
            
            # Still try to get basic DNS data
            try:
                ip = socket.gethostbyname(domain)
                result["data"]["current_ip"] = ip
            except:
                pass
        else:
            # Get subdomain history
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            req = urllib.request.Request(
                url,
                headers={
                    'APIKEY': api_key,
                    'User-Agent': 'Mozilla/5.0'
                }
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
                
                if 'subdomains' in data:
                    subdomains = [f"{s}.{domain}" for s in data['subdomains']]
                    result["data"]["subdomains"] = sorted(subdomains)
                    result["data"]["subdomain_count"] = len(subdomains)
                
                result["data"]["api_response"] = "success"
            
            # Get historical IP changes
            history_url = f"https://api.securitytrails.com/v1/domain/{domain}/history/a"
            req = urllib.request.Request(
                history_url,
                headers={
                    'APIKEY': api_key,
                    'User-Agent': 'Mozilla/5.0'
                }
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
                result["data"]["history"] = data

    except urllib.error.HTTPError as e:
        result["data"]["error"] = f"HTTP error: {e.code}"
        if e.code == 401:
            result["data"]["note"] = "Invalid or missing SecurityTrails API key"
    except urllib.error.URLError as e:
        result["data"]["error"] = str(e.reason)
    except Exception as e:
        result["data"]["error"] = str(e)
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Target required"}, indent=2))
        sys.exit(1)
    
    result = run(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))

