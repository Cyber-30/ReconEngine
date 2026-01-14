#!/usr/bin/env python3
"""
URL Discovery Module
Discovers URLs and endpoints for a target domain.
"""
import sys
import json
import socket
import re
from datetime import datetime
import urllib.request
import urllib.error
import urllib.parse

def run(target: str) -> dict:
    """
    Discover URLs for target domain.
    
    Args:
        target: Target domain
    
    Returns:
        Dictionary containing discovered URLs
    """
    result = {
        "module": "web.urls",
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "urls": [],
            "patterns": {}
        }
    }
    
    try:
        domain = target.lstrip('*.')
        
        # Common URL patterns to check
        url_patterns = [
            f"http://{domain}",
            f"https://{domain}",
            f"http://www.{domain}",
            f"https://www.{domain}",
        ]
        
        # Check which URLs are accessible
        for url in url_patterns:
            try:
                req = urllib.request.Request(
                    url,
                    headers={'User-Agent': 'Mozilla/5.0 (compatible; ReconEngine/1.0)'}
                )
                with urllib.request.urlopen(req, timeout=10, allow_redirects=True) as response:
                    final_url = response.geturl()
                    status = response.status
                    
                    result["data"]["urls"].append({
                        "url": final_url,
                        "status": status,
                        "accessible": True
                    })
            except urllib.error.HTTPError as e:
                result["data"]["urls"].append({
                    "url": url,
                    "status": e.code,
                    "accessible": False
                })
            except urllib.error.URLError:
                result["data"]["urls"].append({
                    "url": url,
                    "status": None,
                    "accessible": False
                })
            except Exception:
                result["data"]["urls"].append({
                    "url": url,
                    "accessible": False
                })
        
        # Try to get sitemap
        for scheme in ['http', 'https']:
            sitemap_url = f"{scheme}://{domain}/sitemap.xml"
            try:
                req = urllib.request.Request(
                    sitemap_url,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                with urllib.request.urlopen(req, timeout=10) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                    # Extract URLs from sitemap
                    urls = re.findall(r'<loc>(.*?)</loc>', content)
                    if urls:
                        result["data"]["sitemap_urls"] = urls[:100]
                        result["data"]["patterns"]["sitemap"] = len(urls)
            except:
                pass
        
        # Get certificate info if HTTPS available
        for url_info in result["data"]["urls"]:
            if url_info.get("url", "").startswith("https"):
                result["data"]["https_available"] = True
                break
        
        result["data"]["url_count"] = len(result["data"]["urls"])
        
    except Exception as e:
        result["data"]["error"] = str(e)
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Target required"}, indent=2))
        sys.exit(1)
    
    result = run(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))

