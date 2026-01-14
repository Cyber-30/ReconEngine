#!/usr/bin/env python3
"""
Shodan Module
Uses Shodan API to gather host and vulnerability information.
"""
import sys
import json
import socket
from datetime import datetime
import urllib.request
import urllib.error

def run(target: str) -> dict:
    """
    Gather information from Shodan for target.
    
    Args:
        target: IP address or domain
    
    Returns:
        Dictionary containing Shodan data
    """
    result = {
        "module": "infra.shodan",
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
        
        # Get API key from config
        api_key = ""  # Add your Shodan API key here
        
        if not api_key:
            result["data"]["note"] = "Shodan API key required. Set in config/api_keys.yaml"
            result["data"]["host_data"] = {}
        else:
            # Get host info
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
                
                result["data"]["host_data"] = {
                    "ip": data.get("ip"),
                    "hostnames": data.get("hostnames", []),
                    "organization": data.get("org"),
                    "os": data.get("os"),
                    "ports": data.get("ports", []),
                    "location": data.get("location"),
                    "vulnerabilities": data.get("vulns", []),
                    "tags": data.get("tags", []),
                    "timestamp": data.get("timestamp"),
                }
                
                # Process services
                services = {}
                if "data" in data:
                    for item in data["data"]:
                        port = item.get("port")
                        if port:
                            services[port] = {
                                "service": item.get("service"),
                                "product": item.get("product"),
                                "version": item.get("version"),
                                "banner": item.get("banner", "")[:200]
                            }
                result["data"]["services"] = services
                
                # Get vulnerability count
                vulns = data.get("vulns", [])
                result["data"]["vulnerability_count"] = len(vulns)
                if vulns:
                    result["data"]["vulnerabilities"] = vulns[:10]  # Limit to 10
        
        # Try to get exploit count
        if api_key:
            try:
                exploit_url = f"https://api.shodan.io/shodan/exploit/search?query={ip}&key={api_key}"
                req = urllib.request.Request(exploit_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=30) as response:
                    exp_data = json.loads(response.read().decode())
                    result["data"]["exploit_count"] = exp_data.get("total", 0)
            except:
                pass
        
    except urllib.error.HTTPError as e:
        result["data"]["error"] = f"HTTP error: {e.code}"
        if e.code == 404:
            result["data"]["note"] = "Host not found in Shodan database"
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

