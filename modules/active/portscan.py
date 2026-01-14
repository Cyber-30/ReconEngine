#!/usr/bin/env python3
"""
Active Port Scanner Module
Performs port scanning using various techniques.
"""
import sys
import json
import socket
from datetime import datetime
import concurrent.futures
import re

# Common ports to scan
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB'
}

# Full port range for comprehensive scan
FULL_PORTS = list(range(1, 1001))

def get_banner(sock: socket.socket, timeout: int = 5) -> str:
    """Try to get service banner."""
    try:
        sock.settimeout(timeout)
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        return banner
    except:
        return ""

def scan_port(target: str, port: int, timeout: int = 3) -> dict:
    """Scan a single port."""
    result = {
        "port": port,
        "state": "closed",
        "service": COMMON_PORTS.get(port, "unknown")
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        conn = sock.connect_ex((target, port))
        
        if conn == 0:
            result["state"] = "open"
            
            # Try to get banner
            banner = get_banner(sock)
            if banner:
                result["banner"] = banner[:200]
            
            # Try to identify service version
            result["service"] = identify_service(port, banner)
            
        sock.close()
        
    except socket.error as e:
        result["error"] = str(e)
    
    return result

def identify_service(port: int, banner: str) -> str:
    """Identify service based on port and banner."""
    services = COMMON_PORT_SERVICES.copy()
    
    # Banner-based detection
    banner_lower = banner.lower()
    if 'ssh' in banner_lower:
        return "SSH"
    elif 'ftp' in banner_lower:
        return "FTP"
    elif 'smtp' in banner_lower or 'mail' in banner_lower:
        return "SMTP"
    elif 'http' in banner_lower:
        return "HTTP"
    elif 'mysql' in banner_lower:
        return "MySQL"
    elif 'postgresql' in banner_lower:
        return "PostgreSQL"
    elif 'redis' in banner_lower:
        return "Redis"
    elif 'mongodb' in banner_lower:
        return "MongoDB"
    
    return COMMON_PORTS.get(port, "unknown")

COMMON_PORT_SERVICES = {}

def run(target: str, ports: str = "common") -> dict:
    """
    Perform port scan on target.
    
    Args:
        target: Target IP or hostname
        ports: Port selection - "common", "full", or comma-separated list
    
    Returns:
        Dictionary containing open ports and services
    """
    result = {
        "module": "active.portscan",
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "ports": [],
            "statistics": {}
        }
    }
    
    try:
        # Resolve hostname to IP
        ip = socket.gethostbyname(target)
        result["data"]["ip"] = ip
        result["data"]["hostname"] = target
        
        # Determine ports to scan
        if ports == "common":
            ports_to_scan = list(COMMON_PORTS.keys())
        elif ports == "full":
            ports_to_scan = FULL_PORTS
        else:
            try:
                ports_to_scan = [int(p) for p in ports.split(',')]
            except:
                ports_to_scan = list(COMMON_PORTS.keys())
        
        result["data"]["ports_scanned"] = len(ports_to_scan)
        
        # Scan ports concurrently
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(scan_port, ip, port): port for port in ports_to_scan}
            
            for future in concurrent.futures.as_completed(futures):
                port_result = future.result()
                if port_result["state"] == "open":
                    open_ports.append(port_result)
        
        # Sort by port number
        open_ports.sort(key=lambda x: x["port"])
        result["data"]["ports"] = open_ports
        result["data"]["open_count"] = len(open_ports)
        
        # Statistics
        services_found = {}
        for port in open_ports:
            svc = port.get("service", "unknown")
            services_found[svc] = services_found.get(svc, 0) + 1
        
        result["data"]["statistics"] = {
            "open_ports": len(open_ports),
            "closed_ports": len(ports_to_scan) - len(open_ports),
            "services": services_found
        }
        
    except socket.gaierror:
        result["data"]["error"] = f"Could not resolve hostname: {target}"
    except socket.error as e:
        result["data"]["error"] = str(e)
    except Exception as e:
        result["data"]["error"] = str(e)
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Target required"}, indent=2))
        sys.exit(1)
    
    target = sys.argv[1]
    ports = sys.argv[2] if len(sys.argv) > 2 else "common"
    
    result = run(target, ports)
    print(json.dumps(result, indent=2, default=str))

