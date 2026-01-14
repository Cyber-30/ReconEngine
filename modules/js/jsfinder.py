#!/usr/bin/env python3
"""
JSFinder Module
Discovers JavaScript files and extracts endpoints.
"""
import sys
import json
import re
from datetime import datetime
import urllib.request
import urllib.error

def run(target: str) -> dict:
    """
    Discover JavaScript files and endpoints for target.
    
    Args:
        target: Target domain
    
    Returns:
        Dictionary containing JS files and endpoints
    """
    result = {
        "module": "js.jsfinder",
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "js_files": [],
            "endpoints": [],
            "domains": []
        }
    }
    
    try:
        domain = target.lstrip('*.')
        
        # Find JS files from sitemap
        for scheme in ['http', 'https']:
            try:
                sitemap_url = f"{scheme}://{domain}/sitemap.xml"
                req = urllib.request.Request(sitemap_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=15) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                    
                    js_files = re.findall(r'<loc>([^<]*\.js[^<]*)</loc>', content, re.IGNORECASE)
                    result["data"]["js_files"] = list(set(js_files))[:50]
            except:
                pass
        
        # If no sitemap, try to fetch homepage and find JS
        if not result["data"]["js_files"]:
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{domain}"
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=15) as response:
                        content = response.read().decode('utf-8', errors='ignore')
                        
                        js_files = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', content)
                        result["data"]["js_files"] = list(set(js_files))[:20]
                        
                        # Also find relative paths and make them absolute
                        for js in result["data"]["js_files"][:5]:
                            if not js.startswith('http'):
                                result["data"]["js_files"].append(f"{url}/{js.lstrip('/')}")
                except:
                    pass
        
        # Scan JS files for endpoints
        endpoints = set()
        found_domains = set()
        
        for js_url in result["data"]["js_files"][:10]:
            try:
                req = urllib.request.Request(js_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=15) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                    
                    # Find URLs
                    found_urls = re.findall(r'(?:https?://[^\s"\'<>\)]+)', content)
                    for url in found_urls:
                        if len(url) > 10 and len(url) < 500:
                            endpoints.add(url)
                            
                            # Extract domains
                            match = re.search(r'https?://([^/]+)', url)
                            if match:
                                found_domains.add(match.group(1))
                                
            except Exception as e:
                pass
        
        result["data"]["endpoints"] = sorted(list(endpoints))[:100]
        result["data"]["domains"] = sorted(list(found_domains))
        result["data"]["js_count"] = len(result["data"]["js_files"])
        result["data"]["endpoint_count"] = len(result["data"]["endpoints"])
        
    except Exception as e:
        result["data"]["error"] = str(e)
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Target required"}, indent=2))
        sys.exit(1)
    
    result = run(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))

