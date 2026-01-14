#!/usr/bin/env python3
"""
Censys Module
Uses Censys API to gather host and certificate information.
"""
import sys
import json
import socket
from datetime import datetime
import urllib.request
import urllib.error

def run(target: str) -> dict:
    """
    Gather information from Censys for target.
    
    Args:
        target: IP address or domain
    
    Returns:
        Dictionary containing Censys data
    """
    result = {
        "module": "infra.censys",
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "data": {}
    }
    
    try:
        # Resolve to IP if domain
        ip = target
        try:
            socket.inet_aton(target)
        except socket.error:
            ip = socket.gethostbyname(target)
            result["data"]["resolved_ip"] = ip
        
        result["data"]["query_ip"] = ip
        
        # Get API credentials from config
        api_id = ""  # Add your Censys API ID
        api_secret = ""  # Add your Censys API Secret
        
        if not api_id or not api_secret:
            result["data"]["note"] = "Censys API credentials required. Set in config/api_keys.yaml"
            result["data"]["host_data"] = {}
        else:
            # Get host data
            url = f"https://search.censys.io/api/v2/hosts/{ip}"
            req = urllib.request.Request(url)
            credentials = f"{api_id}:{api_secret}"
            encoded = credentials.encode()
            req.add_header('Authorization', 'Basic ' + encoded.decode())
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
                
                if data.get("status") == "ok":
                    result["data"]["host_data"] = {
                        "ip": ip,
                        "first_seen": data.get("first_seen"),
                        "last_seen": data.get("last_seen"),
                        "建国": data.get("建国"),
                        "autonomous_system": data.get("autonomous_system"),
                        "location": data.get("location"),
                        "os": data.get("os"),
                        "hostnames": data.get("hostnames", []),
                        "tags": data.get("tags", []),
                    }
                    
                    # Process services
                    services = []
                    for service in data.get("services", []):
                        services.append({
                            "port": service.get("port"),
                            "service_name": service.get("service_name"),
                            "transport_protocol": service.get("transport_protocol"),
                            "certificate": service.get("certificate")
                        })
                    result["data"]["services"] = services
                    result["data"]["port_count"] = len(services)
                    
                    # Get certificate info
                    for service in services:
                        if service.get("certificate"):
                            result["data"]["has_certificate"] = True
                            break
        
        # Search for certificates
        if api_id and api_secret:
            try:
                cert_url = f"https://search.censys.io/api/v2/certificates/search"
                params = f"parsed.subject_dn_keywords={ip}"
                req = urllib.request.Request(f"{cert_url}?{params}")
                encoded = f"{api_id}:{api_secret}".encode()
                req.add_header('Authorization', 'Basic ' + encoded.decode())
                
                with urllib.request.urlopen(req, timeout=30) as response:
                    cert_data = json.loads(response.read().decode())
                    result["data"]["certificate_count"] = cert_data.get("total", 0)
            except:
                pass
        
    except urllib.error.HTTPError as e:
        result["data"]["error"] = f"HTTP error: {e.code}"
        if e.code == 404:
            result["data"]["note"] = "Host not found in Censys database"
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

