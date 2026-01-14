#!/usr/bin/env python3
"""
Wayback Machine Module
Discovers archived URLs and endpoints using the Wayback Machine.
"""
import sys
import json
import urllib.parse
from datetime import datetime
import urllib.request
import urllib.error

def run(target: str) -> dict:
    """
    Discover archived URLs for target using Wayback Machine.
    
    Args:
        target: Target domain
    
    Returns:
        Dictionary containing archived URLs and endpoints
    """
    result = {
        "module": "web.wayback",
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "urls": [],
            "statistics": {}
        }
    }
    
    try:
        domain = target.lstrip('*.')
        base_domain = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
        
        # CDX API endpoint
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&limit=10000&filter=statuscode:200"
        
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        
        with urllib.request.urlopen(req, timeout=60) as response:
            data = response.read().decode('utf-8').strip()
            
            if data:
                lines = data.split('\n')
                if len(lines) > 1:
                    # First line is header, skip it
                    urls = set()
                    file_extensions = {}
                    
                    for line in lines[1:]:
                        parts = line.split(',')
                        if len(parts) >= 2:
                            original_url = parts[0]
                            timestamp = parts[1]
                            
                            urls.add(original_url)
                            
                            # Extract file extension
                            parsed = urllib.parse.urlparse(original_url)
                            ext = parsed.path.split('.')[-1].lower() if '.' in parsed.path else 'unknown'
                            if len(ext) <= 5 and ext.isalpha():
                                file_extensions[ext] = file_extensions.get(ext, 0) + 1
                    
                    result["data"]["urls"] = sorted(list(urls))[:1000]  # Limit to 1000
                    result["data"]["count"] = len(result["data"]["urls"])
                    result["data"]["total_discovered"] = len(urls)
                    result["data"]["extensions"] = dict(sorted(file_extensions.items(), key=lambda x: x[1], reverse=True)[:10])
                    
                    # Get statistics
                    stats_url = f"https://web.archive.org/__wb/timemap/json?url=*.{domain}/*&filter=statuscode:200"
                    stats_req = urllib.request.Request(stats_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(stats_req, timeout=30) as stats_response:
                        stats_data = json.loads(stats_response.read().decode())
                        if isinstance(stats_data, dict) and 'first_ts' in stats_data:
                            result["data"]["first_capture"] = stats_data['first_ts']
                            result["data"]["last_capture"] = stats_data.get('last_ts')

    except urllib.error.HTTPError as e:
        result["data"]["error"] = f"HTTP error: {e.code}"
    except urllib.error.URLError as e:
        result["data"]["error"] = str(e.reason)
    except json.JSONDecodeError:
        result["data"]["urls"] = []
        result["data"]["note"] = "No archived URLs found or API returned non-JSON response"
    except Exception as e:
        result["data"]["error"] = str(e)
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Target required"}, indent=2))
        sys.exit(1)
    
    result = run(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))

