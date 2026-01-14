#!/usr/bin/env python3
"""
WHOIS Lookup Module
Performs WHOIS lookups for domains and IP addresses.
"""
import sys
import json
import socket
from datetime import datetime
import whois

def run(target: str) -> dict:
    """
    Perform WHOIS lookup on target.
    
    Args:
        target: Domain name or IP address
    
    Returns:
        Dictionary containing WHOIS information
    """
    result = {
        "module": "domains.whois",
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "query": target,
            "type": "domain"
        }
    }
    
    try:
        # Check if target is an IP address
        try:
            socket.inet_aton(target)
            result["data"]["type"] = "ip"
            result["data"]["ip"] = target
            # For IP WHOIS, we'd need a different API
            result["data"]["note"] = "IP WHOIS requires specialized service"
            result["data"]["status"] = "ip_address_detected"
        except socket.error:
            # It's a domain, perform WHOIS lookup
            domain_info = whois.whois(target)
            
            result["data"]["status"] = "success"
            result["data"]["domain_name"] = domain_info.domain_name
            result["data"]["registrar"] = str(domain_info.registrar) if domain_info.registrar else None
            result["data"]["whois_server"] = domain_info.whois_server
            
            # Dates
            dates = {}
            for attr in ['creation_date', 'expiration_date', 'updated_date']:
                val = getattr(domain_info, attr, None)
                if val:
                    if isinstance(val, list):
                        dates[attr] = [d.isoformat() if isinstance(d, datetime) else str(d) for d in val]
                    elif isinstance(val, datetime):
                        dates[attr] = val.isoformat()
                    else:
                        dates[attr] = str(val)
            if dates:
                result["data"]["dates"] = dates
            
            # Name servers
            if domain_info.name_servers:
                result["data"]["nameservers"] = [str(ns).lower() for ns in domain_info.name_servers if ns]
            
            # Status
            if domain_info.status:
                result["data"]["domain_status"] = [str(s) for s in domain_info.status]
            
            # DNSSEC
            result["data"]["dnssec"] = str(domain_info.dnssec) if domain_info.dnssec else None
            
            # Emails
            if domain_info.emails:
                result["data"]["contacts"] = {
                    "emails": [e for e in domain_info.emails if e]
                }
            
            # Registrar info
            if domain_info.registrar:
                result["data"]["registrar_info"] = {
                    "name": str(domain_info.registrar),
                    "url": domain_info.url
                }
            
    except whois.parser.PywhoisError as e:
        result["data"]["status"] = "error"
        result["data"]["error"] = f"WHOIS error: {str(e)}"
    except Exception as e:
        result["data"]["status"] = "error"
        result["data"]["error"] = str(e)
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Target required"}, indent=2))
        sys.exit(1)
    
    result = run(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))

