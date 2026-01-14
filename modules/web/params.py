#!/usr/bin/env python3
"""
Parameter Discovery Module
Discovers URL parameters and sensitive parameters in web applications.
"""
import sys
import json
import re
from datetime import datetime
import urllib.request
import urllib.error

# Sensitive parameter names
SENSITIVE_PARAMS = {
    "authentication": ["token", "auth", "password", "passwd", "pwd", "secret", "key", "api_key", "apikey", "session_id", "jwt"],
    "personal": ["email", "phone", "mobile", "address", "name", "first_name", "last_name", "ssn", "dob"],
    "financial": ["card", "credit", "cvv", "bank", "account", "routing"],
    "debug": ["debug", "verbose", "trace", "log", "admin", "dev", "test"]
}

def run(target: str) -> dict:
    """
    Discover URL parameters for target.
    
    Args:
        target: Target domain
    
    Returns:
        Dictionary containing discovered parameters
    """
    result = {
        "module": "web.params",
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "parameters": [],
            "sensitive": [],
            "forms": []
        }
    }
    
    try:
        domain = target.lstrip('*.')
        
        # Try to get sitemap for URLs with parameters
        for scheme in ['http', 'https']:
            try:
                sitemap_url = f"{scheme}://{domain}/sitemap.xml"
                req = urllib.request.Request(sitemap_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=15) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                    
                    # Find URLs with parameters
                    urls_with_params = re.findall(r'<loc>([^<]*\?[^\s<]*)</loc>', content)
                    result["data"]["urls_with_params"] = urls_with_params[:100]
                    
                    # Extract parameters
                    all_params = set()
                    sensitive_found = []
                    
                    for url in urls_with_params[:50]:
                        parsed = urllib.parse.urlparse(url)
                        params = urllib.parse.parse_qsl(parsed.query)
                        for name, value in params:
                            all_params.add(name.lower())
                            
                            # Check if sensitive
                            for category, keywords in SENSITIVE_PARAMS.items():
                                if any(kw in name.lower() for kw in keywords):
                                    sensitive_found.append({
                                        "parameter": name,
                                        "category": category,
                                        "url": url[:200]
                                    })
                    
                    result["data"]["parameters"] = sorted(list(all_params))
                    result["data"]["parameter_count"] = len(all_params)
                    result["data"]["sensitive"] = sensitive_found
                    
            except:
                pass
        
        # Try common admin/login paths
        common_paths = ['/admin', '/login', '/dashboard', '/api', '/wp-admin']
        forms_found = []
        
        for path in common_paths:
            for scheme in ['http', 'https']:
                url = f"{scheme}://{domain}{path}"
                try:
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=10) as response:
                        if response.status == 200:
                            content = response.read().decode('utf-8', errors='ignore')
                            
                            # Find forms
                            forms = re.findall(r'<form[^>]*>', content)
                            for form in forms[:5]:
                                form_info = {
                                    "url": url,
                                    "action": re.search(r'action=["\']([^"\']*)["\']', form),
                                    "method": re.search(r'method=["\']([^"\']*)["\']', form),
                                    "inputs": re.findall(r'<input[^>]*>', content)
                                }
                                if form_info["action"]:
                                    form_info["action"] = form_info["action"].group(1)
                                if form_info["method"]:
                                    form_info["method"] = form_info["method"].group(1)
                                forms_found.append(form_info)
                                
                except:
                    pass
        
        result["data"]["forms"] = forms_found
        
    except Exception as e:
        result["data"]["error"] = str(e)
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Target required"}, indent=2))
        sys.exit(1)
    
    result = run(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))

