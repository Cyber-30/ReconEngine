#!/usr/bin/env python3
"""
ASN Lookup Module
Finds Autonomous System Numbers for IP addresses.
Uses Team Cymru and BGPView APIs.
"""
import sys
import json
import socket
from datetime import datetime
import urllib.request
import urllib.error

def run(target: str) -> dict:
    """
    Perform ASN lookup for target (IP or domain).
    
    Args:
        target: IP address or domain
    
    Returns:
        Dictionary containing ASN information
    """
    result = {
        "module": "domains.asn",
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "data": {}
    }
    
    try:
        # If target is a domain, resolve to IP
        ip = target
        try:
            socket.inet_aton(target)
        except socket.error:
            # It's a domain, resolve it
            ip = socket.gethostbyname(target)
            result["data"]["resolved_ip"] = ip
        
        result["data"]["query_ip"] = ip
        
        # Try Team Cymru IP to ASN service
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(('whois.cymru.com', 43))
            sock.send(f" -v {ip}\r\n".encode())
            response = sock.recv(4096).decode()
            sock.close()
            
            lines = response.strip().split('\n')
            if len(lines) > 1:
                # Parse Team Cymru response
                asn_info = lines[1].split('|')
                if len(asn_info) >= 5:
                    result["data"]["asn"] = asn_info[0].strip()
                    result["data"]["prefix"] = asn_info[1].strip()
                    result["data"]["country"] = asn_info[2].strip()
                    result["data"]["registry"] = asn_info[3].strip()
                    result["data"]["allocated"] = asn_info[4].strip()
        except Exception as e:
            result["data"]["cymru_error"] = str(e)
        
        # Try BGPView API for more details
        try:
            url = f"https://api.bgpview.io/ip/{ip}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode())
                
                if data.get('status') == 'ok':
                    if data.get('data', {}).get('prefixes'):
                        prefixes = []
                        for p in data['data']['prefixes']:
                            prefixes.append({
                                "prefix": p.get('prefix'),
                                "rir": p.get('rir'),
                                "date": p.get('allocation_date'),
                                "status": p.get('status')
                            })
                        result["data"]["prefixes"] = prefixes
                    
                    if data.get('data', {}).get('asn'):
                        asn_data = data['data']['asn']
                        result["data"]["asn_details"] = {
                            "asn": asn_data.get('asn'),
                            "name": asn_data.get('name'),
                            "description": asn_data.get('description'),
                            "country_code": asn_data.get('country_code'),
                            "website": asn_data.get('website'),
                            "looking_glass": asn_data.get('looking_glass'),
                            "route_server": asn_data.get('route_server')
                        }
                    
                    if data.get('data', {}).get('prefixes'):
                        result["data"]["roa_status"] = "valid"
        except Exception as e:
            result["data"]["bgpview_error"] = str(e)
        
        # Get reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            result["data"]["hostname"] = hostname
        except socket.herror:
            result["data"]["hostname"] = None
        
    except socket.gaierror as e:
        result["data"]["error"] = f"DNS resolution error: {str(e)}"
    except Exception as e:
        result["data"]["error"] = str(e)
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Target required"}, indent=2))
        sys.exit(1)
    
    result = run(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))

