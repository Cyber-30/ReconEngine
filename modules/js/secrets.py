#!/usr/bin/env python3
"""
JavaScript Secrets Scanner Module
Scans JavaScript files for hardcoded secrets and sensitive data.
"""
import sys
import json
import re
from datetime import datetime
import urllib.request
import urllib.error
import urllib.parse

# Patterns for common secrets
SECRET_PATTERNS = {
    "aws_access_key": r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
    "aws_secret_key": r'(?i)aws(.{0,20})?(?-i)[0-9a-zA-Z/+]{40}',
    "google_api_key": r'AIza[0-9A-Za-z\\-_]{35}',
    "github_token": r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}',
    "slack_token": r'xox[baprs]-([0-9a-zA-Z]{10,48})',
    "private_key": r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    "jwt_token": r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
    "stripe_key": r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}',
    "firebase_key": r'AIza[0-9A-Za-z\\-_]{35}',
    "sendgrid_key": r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
    "twilio_key": r'SK[0-9a-fA-F]{32}',
    "mailgun_key": r'key-[0-9a-zA-Z]{32}',
    "generic_api_key": r'(?i)(?:api|apikey|access|secret|password|auth)(?:.{0,20})?[=:\s]["\']([a-zA-Z0-9_\-]{16,})["\']',
    "basic_auth": r'(?i)basic\s+[a-zA-Z0-9+/=]+',
    "bearer_token": r'(?i)bearer\s+[a-zA-Z0-9_\-\.=]+',
    "cookie_secret": r'(?i)cookie.?secret["\']?\s*[=:\s]["\']([^"\'\s]{16,})["\']',
    "database_url": r'(?i)(?:postgres|postgresql|mysql|mongodb|redis)://[^\s"\']+',
    "endpoint_url": r'https?://[^\s"\']+',
}

def run(target: str) -> dict:
    """
    Scan for JavaScript files and extract secrets.
    
    Args:
        target: Target domain
    
    Returns:
        Dictionary containing found JS files and secrets
    """
    result = {
        "module": "js.secrets",
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "files": [],
            "secrets": [],
            "endpoints": [],
            "patterns_found": {}
        }
    }
    
    try:
        domain = target.lstrip('*.')
        
        # Try to get sitemap for JS files
        for scheme in ['http', 'https']:
            try:
                sitemap_url = f"{scheme}://{domain}/sitemap.xml"
                req = urllib.request.Request(sitemap_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=15) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                    
                    # Find JS files
                    js_files = re.findall(r'<loc>([^<]*\.js[^<]*)</loc>', content, re.IGNORECASE)
                    result["data"]["files"].extend(js_files[:50])  # Limit to 50
            except:
                pass
        
        # If no sitemap, try common JS paths
        if not result["data"]["files"]:
            common_js_paths = [
                f"https://{domain}/app.js",
                f"https://{domain}/main.js",
                f"https://{domain}/bundle.js",
                f"https://{domain}/script.js",
                f"https://{domain}/assets/js/app.js",
                f"https://{domain}/static/js/main.js",
            ]
            
            for js_url in common_js_paths:
                try:
                    req = urllib.request.Request(js_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=10) as response:
                        if response.status == 200:
                            result["data"]["files"].append(js_url)
                except:
                    pass
        
        # Scan JS files for secrets
        secrets_found = {}
        
        for js_url in result["data"]["files"][:20]:  # Limit to 20 files
            try:
                req = urllib.request.Request(js_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=15) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                    
                    # Check for each pattern
                    for pattern_name, pattern in SECRET_PATTERNS.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            if pattern_name not in secrets_found:
                                secrets_found[pattern_name] = []
                            for match in matches[:5]:  # Limit matches per pattern
                                secrets_found[pattern_name].append({
                                    "file": js_url,
                                    "match": str(match)[:100]  # Truncate
                                })
                    
                    # Find URLs/endpoints in JS
                    endpoints = re.findall(r'(?:https?://[^\s"\'<>\)]+)', content)
                    for ep in endpoints[:10]:
                        if ep not in result["data"]["endpoints"]:
                            result["data"]["endpoints"].append(ep)
                            
            except Exception as e:
                result["data"]["scan_errors"] = result.get("scan_errors", []) + [str(e)]
        
        result["data"]["secrets"] = secrets_found
        result["data"]["file_count"] = len(result["data"]["files"])
        result["data"]["secret_count"] = sum(len(v) for v in secrets_found.values())
        
    except Exception as e:
        result["data"]["error"] = str(e)
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Target required"}, indent=2))
        sys.exit(1)
    
    result = run(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))

