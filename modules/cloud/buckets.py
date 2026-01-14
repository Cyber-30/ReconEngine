#!/usr/bin/env python3
"""
Cloud Bucket Discovery Module
Discovers potential cloud storage buckets for a target.
"""
import sys
import json
from datetime import datetime
import urllib.request
import urllib.error

def run(target: str) -> dict:
    """
    Discover potential cloud storage buckets for target.
    
    Args:
        target: Target domain or company name
    
    Returns:
        Dictionary containing discovered bucket URLs
    """
    result = {
        "module": "cloud.buckets",
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "data": {
            "buckets": [],
            "types": {
                "aws_s3": [],
                "azure_blob": [],
                "gcp_storage": [],
                "digitalocean": []
            }
        }
    }
    
    try:
        domain = target.lstrip('*.')
        company = domain.split('.')[0] if '.' in domain else domain
        
        # Common bucket naming patterns
        patterns = [
            company,
            f"{company}-www",
            f"www-{company}",
            f"{company}-assets",
            f"assets-{company}",
            f"{company}-files",
            f"files-{company}",
            f"{company}-backup",
            f"backup-{company}",
            f"{company}-logs",
            f"logs-{company}",
            f"{company}-public",
            f"public-{company}",
            f"{company}-private",
            f"private-{company}",
            f"{company}-dev",
            f"dev-{company}",
            f"{company}-staging",
            f"staging-{company}",
            f"{company}-prod",
            f"prod-{company}",
            domain.replace('.', '-'),
            domain.replace('.', ''),
        ]
        
        buckets = []
        
        # Check AWS S3 buckets
        for pattern in set(patterns):
            bucket_url = f"https://{pattern}.s3.amazonaws.com"
            bucket_info = {
                "url": bucket_url,
                "type": "aws_s3",
                "pattern": pattern,
                "exists": False
            }
            
            try:
                req = urllib.request.Request(
                    bucket_url,
                    method='HEAD',
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                with urllib.request.urlopen(req, timeout=10) as response:
                    if response.status == 200:
                        bucket_info["exists"] = True
                        bucket_info["access"] = "public"
                    elif response.status == 403:
                        bucket_info["exists"] = True
                        bucket_info["access"] = "private"
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    bucket_info["exists"] = True
                    bucket_info["access"] = "private"
                elif e.code == 404:
                    bucket_info["exists"] = False
            except:
                pass
            
            if bucket_info["exists"]:
                buckets.append(bucket_info)
        
        # Check AWS S3 with region
        aws_regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']
        for pattern in set(patterns)[:5]:
            for region in aws_regions:
                bucket_url = f"https://{pattern}.s3-{region}.amazonaws.com"
                bucket_info = {
                    "url": bucket_url,
                    "type": "aws_s3",
                    "pattern": pattern,
                    "region": region,
                    "exists": False
                }
                
                try:
                    req = urllib.request.Request(
                        bucket_url,
                        method='HEAD',
                        headers={'User-Agent': 'Mozilla/5.0'}
                    )
                    with urllib.request.urlopen(req, timeout=10) as response:
                        bucket_info["exists"] = True
                        bucket_info["access"] = "public" if response.status == 200 else "private"
                        buckets.append(bucket_info)
                except urllib.error.HTTPError as e:
                    if e.code == 403:
                        bucket_info["exists"] = True
                        bucket_info["access"] = "private"
                        buckets.append(bucket_info)
                except:
                    pass
        
        # Check Azure Blob Storage
        for pattern in set(patterns):
            blob_url = f"https://{pattern}.blob.core.windows.net/{pattern}"
            bucket_info = {
                "url": blob_url,
                "type": "azure_blob",
                "pattern": pattern,
                "exists": False
            }
            
            try:
                req = urllib.request.Request(
                    blob_url,
                    method='HEAD',
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                with urllib.request.urlopen(req, timeout=10) as response:
                    bucket_info["exists"] = True
                    bucket_info["access"] = "public" if response.status == 200 else "private"
                    buckets.append(bucket_info)
            except urllib.error.HTTPError:
                pass
            except:
                pass
        
        # Check GCP Storage
        for pattern in set(patterns):
            gcp_url = f"https://storage.googleapis.com/{pattern}"
            bucket_info = {
                "url": gcp_url,
                "type": "gcp_storage",
                "pattern": pattern,
                "exists": False
            }
            
            try:
                req = urllib.request.Request(
                    gcp_url,
                    method='HEAD',
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                with urllib.request.urlopen(req, timeout=10) as response:
                    bucket_info["exists"] = True
                    bucket_info["access"] = "public" if response.status == 200 else "private"
                    buckets.append(bucket_info)
            except urllib.error.HTTPError:
                pass
            except:
                pass
        
        result["data"]["buckets"] = buckets
        result["data"]["bucket_count"] = len(buckets)
        
        # Categorize by type
        for bucket in buckets:
            btype = bucket["type"]
            if btype in result["data"]["types"]:
                result["data"]["types"][btype].append(bucket)
        
    except Exception as e:
        result["data"]["error"] = str(e)
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Target required"}, indent=2))
        sys.exit(1)
    
    result = run(sys.argv[1])
    print(json.dumps(result, indent=2, default=str))

