#!/usr/bin/env python3
"""
IPIntel Module
Gathers IP reputation and geolocation data.
"""
import sys
import json
import socket
from datetime import datetime
import urllib.request
import urllib.error

def run(target: str) -> dict:
    """
    Gather IP intelligence data for target.
    
    Args:
        target: IP address or domain
    
    Returns:
        Dictionary containing IP intelligence data
    """
    result = {
        "module": "infra.ipintel",
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
        
        # Get reverse hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            result["data"]["hostname"] = hostname
        except socket.herror:
            result["data"]["hostname"] = None
        
        # Get geolocation (using ip-api.com - free tier)
        try:
            geo_url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting"
            req = urllib.request.Request(geo_url, headers={'User-Agent': 'Mozilla/5.0'})
            
            with urllib.request.urlopen(req, timeout=15) as response:
                geo_data = json.loads(response.read().decode())
                
                if geo_data.get("status") == "success":
                    result["data"]["geolocation"] = {
                        "country": geo_data.get("country"),
                        "country_code": geo_data.get("countryCode"),
                        "region": geo_data.get("regionName"),
                        "city": geo_data.get("city"),
                        "zip": geo_data.get("zip"),
                        "coordinates": {
                            "latitude": geo_data.get("lat"),
                            "longitude": geo_data.get("lon")
                        },
                        "timezone": geo_data.get("timezone"),
                        "isp": geo_data.get("isp"),
                        "organization": geo_data.get("org"),
                        "as": geo_data.get("as"),
                        "as_name": geo_data.get("asname"),
                        "reverse_dns": geo_data.get("reverse"),
                        "mobile": geo_data.get("mobile"),
                        "proxy": geo_data.get("proxy"),
                        "hosting": geo_data.get("hosting")
                    }
                    
                    # Flag suspicious indicators
                    flags = []
                    if geo_data.get("proxy"):
                        flags.append("proxy")
                    if geo_data.get("hosting"):
                        flags.append("hosting")
                    if geo_data.get("mobile"):
                        flags.append("mobile")
                    
                    if flags:
                        result["data"]["flags"] = flags
                    
                else:
                    result["data"]["geo_error"] = "Failed to get geolocation"
        except Exception as e:
            result["data"]["geo_error"] = str(e)
        
        # Check for abuse history (AbuseIPDB free tier)
        try:
            abuse_url = "https://api.abuseipdb.com/api/v2/check"
            params = f"ipAddress={ip}&maxAgeInDays=90"
            req = urllib.request.Request(f"{abuse_url}?{params}")
            req.add_header("Accept", "application/json")
            # Add API key header if available
            # req.add_header("Api-Key", "your-api-key")
            
            with urllib.request.urlopen(req, timeout=15) as response:
                abuse_data = json.loads(response.read().decode())
                result["data"]["abuseipdb"] = {
                    "abuse_confidence_score": abuse_data.get("data", {}).get("abuseConfidenceScore"),
                    "total_reports": abuse_data.get("data", {}).get("totalReports"),
                    "num_distinct_users": abuse_data.get("data", {}).get("numDistinctUsers"),
                    "last_reported": abuse_data.get("data", {}).get("lastReportedAt"),
                    "is_whitelisted": abuse_data.get("data", {}).get("isWhitelisted")
                }
        except Exception as e:
            result["data"]["abuseipdb_error"] = str(e)
        
    except socket.gaierror:
        result["data"]["error"] = f"Could not resolve: {target}"
    except Exception as e:
        result["data"]["error"] = str(e)
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Target required"}, indent=2))
        sys.exit(1)
    
    result = run(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))

