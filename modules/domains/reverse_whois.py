#!/usr/bin/env python3
"""
Reverse WHOIS Module
Finds domains owned by the same entity using reverse WHOIS lookups.
"""
import sys
import json
import urllib.parse
from datetime import datetime
import urllib.request
import urllib.error

def run(target: str) -> dict:
    """
    Perform reverse WHOIS lookup.
    
    Args:
        target: Email, name, or organization to search for
    
    Returns:
        Dictionary containing domains found via reverse WHOIS
    """
    result = {
        "module": "domains.reverse_whois",
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "domains": [],
            "search_type": "unknown"
        }
    }
    
    try:
        # Determine search type
        if '@' in target:
            search_type = "email"
            result["data"]["search_type"] = "email"
        elif target.replace('.', '').replace('-', '').isalpha():
            search_type = "name"
            result["data"]["search_type"] = "name"
        else:
            search_type = "organization"
            result["data"]["search_type"] = "organization"
        
        # Use ViewDNS Reverse WHOIS API (free tier available)
        api_key = ""  # Add your API key here
        
        if not api_key:
            result["data"]["note"] = "Reverse WHOIS API key required. Consider using viewdns.info or whoisxmlapi.com"
            result["data"]["domains"] = []
            result["data"]["alternative"] = "Try searching manually at https://viewdns.info/reversewhois/"
        else:
            url = f"https://reverse-whois-api.whoisxmlapi.com/api/v2"
            req = urllib.request.Request(
                url,
                data=json.dumps({"searchType": search_type, "term": target}).encode(),
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Basic {api_key}',
                    'User-Agent': 'Mozilla/5.0'
                }
            )
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
                result["data"]["domains"] = data.get('domainsList', {}).get('domainName', [])
                result["data"]["count"] = len(result["data"]["domains"])
        
    except urllib.error.HTTPError as e:
        result["data"]["error"] = f"HTTP error: {e.code}"
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

