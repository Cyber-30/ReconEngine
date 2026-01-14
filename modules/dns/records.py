#!/usr/bin/env python3
"""
DNS Records Module
Performs DNS lookups for various record types.
"""
import sys
import json
import socket
from datetime import datetime
import dns.resolver
import dns.reversename

def run(target: str) -> dict:
    """
    Perform DNS record lookups on target.
    
    Args:
        target: Domain name or IP address
    
    Returns:
        Dictionary containing DNS records
    """
    result = {
        "module": "dns.records",
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "data": {}
    }
    
    try:
        # Determine if target is IP or domain
        is_ip = False
        try:
            socket.inet_aton(target)
            is_ip = True
        except socket.error:
            pass
        
        if is_ip:
            # Reverse DNS for IP
            rev_name = dns.reversename.from_address(target)
            try:
                ans = dns.resolver.resolve(rev_name, 'PTR')
                result["data"]["ptr"] = [str(r) for r in ans]
            except dns.resolver.NXDOMAIN:
                result["data"]["ptr"] = []
            except Exception as e:
                result["data"]["ptr_error"] = str(e)
        else:
            # Forward DNS for domain
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'SRV', 'CAA', 'HINFO']
            
            for rtype in record_types:
                try:
                    ans = dns.resolver.resolve(target, rtype, lifetime=10)
                    records = []
                    for rdata in ans:
                        if rtype == 'MX':
                            records.append({"priority": rdata.preference, "exchange": str(rdata.exchange)})
                        elif rtype == 'SOA':
                            records.append({
                                "ns": str(rdata.mname),
                                "email": str(rdata.rname),
                                "serial": rdata.serial,
                                "refresh": rdata.refresh,
                                "retry": rdata.retry,
                                "expire": rdata.expire,
                                "minimum": rdata.minimum
                            })
                        elif rtype == 'SRV':
                            records.append({
                                "priority": rdata.priority,
                                "weight": rdata.weight,
                                "port": rdata.port,
                                "target": str(rdata.target)
                            })
                        elif rtype == 'TXT':
                            records.append(str(rdata).strip('"'))
                        else:
                            records.append(str(rdata))
                    
                    if records:
                        # Normalize key name
                        key = rtype.lower()
                        result["data"][key] = records
                        
                except dns.resolver.NXDOMAIN:
                    result["data"][rtype.lower()] = []
                except dns.resolver.NoAnswer:
                    pass
                except dns.resolver.Timeout:
                    result["data"][rtype.lower()] = ["timeout"]
                except Exception as e:
                    result["data"][rtype.lower()] = {"error": str(e)}
            
            # Additional info
            result["data"]["resolution_success"] = True
            
    except Exception as e:
        result["data"]["error"] = str(e)
        result["data"]["resolution_success"] = False
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Target required"}, indent=2))
        sys.exit(1)
    
    result = run(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))

