#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CloudSniper
Author: Decryptious_ on Discord / Punchborn on IG
A cross-platform cloud storage reconnaissance tool for AWS S3, Azure Blob, and GCP Storage.
For authorized security testing only.
"""

import sys
import os
import json
import argparse
import threading
import time
import re
import random
import platform
from urllib.parse import urljoin, urlparse, quote
from datetime import datetime

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Missing dependency: requests")
    print("[*] Install: pip install -r requirements.txt")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class DummyFore:
        def __getattr__(self, name): return ''
    class DummyStyle:
        def __getattr__(self, name): return ''
    Fore = DummyFore()
    Style = DummyStyle()

# ── TITLE BLOCK ──
def print_title():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'CloudSniper':^60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'Cloud Storage Reconnaissance Tool':^60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  Author: Decryptious_ on Discord / Punchborn on IG{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  Platforms: Linux | Windows | macOS{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  Services: AWS S3 | Azure Blob | GCP Storage{Style.RESET_ALL}")
    print(f"{Fore.RED}  For authorized security testing only{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print()

# ── USER AGENTS ──
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0 botocore/1.31.0"
]

class CloudSniper:
    def __init__(self, target, threads=20, timeout=15, output=None, verbose=False, services=None):
        self.target = target.lower().strip()
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.output_file = output
        self.services = services or ['aws', 'azure', 'gcp']
        self.found = []
        self.checked = 0
        self.total = 0
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        
    def _generate_bucket_names(self):
        """Generate permutations of potential bucket/container names"""
        base_names = []
        clean_target = re.sub(r'https?://', '', self.target).strip('/')
        domain_parts = clean_target.replace('www.', '').split('.')
        
        # Base variations
        base_names.append(clean_target)
        base_names.append(domain_parts[0])
        
        # Common suffixes/prefixes
        suffixes = ['', '-prod', '-dev', '-staging', '-test', '-backup', '-archive',
                   '-data', '-assets', '-media', '-files', '-uploads', '-static',
                   '-public', '-private', '-internal', '-temp', '-logs', '-db',
                   '-database', '-storage', '-bucket', '-container', '-images',
                   '-videos', '-documents', '-backups', '-old', '-new', '-v1', '-v2',
                   'prod-', 'dev-', 'staging-', 'test-', 'backup-', 'archive-',
                   'data-', 'assets-', 'media-', 'files-', 'uploads-', 'static-',
                   'public-', 'private-', 'internal-', 'temp-', 'logs-', 'db-',
                   'database-', 'storage-', 'bucket-', 'container-', 'images-',
                   'videos-', 'documents-', 'backups-', 'old-', 'new-', 'v1-', 'v2-']
        
        prefixes = ['', 'my', 'the', 'our', 'company', 'corp', 'app', 'web',
                   'api', 'cdn', 'static', 'media', 'content', 'user', 'customer',
                   'client', 'project', 'service', 'prod', 'dev', 'staging', 'test']
        
        permutations = set()
        for name in base_names:
            for suffix in suffixes:
                permutations.add(f"{name}{suffix}")
                permutations.add(f"{suffix.lstrip('-')}{name}")
            for prefix in prefixes:
                if prefix:
                    permutations.add(f"{prefix}-{name}")
                    permutations.add(f"{prefix}{name}")
        
        # Add target exactly as provided
        permutations.add(self.target.replace('https://', '').replace('http://', '').strip('/'))
        
        return list(permutations)
    
    def _check_aws_s3(self, bucket_name):
        """Check AWS S3 bucket existence and permissions"""
        endpoints = [
            f"https://{bucket_name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{bucket_name}",
            f"https://{bucket_name}.s3-website-us-east-1.amazonaws.com",
        ]
        
        for url in endpoints:
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                status = resp.status_code
                
                with self.lock:
                    self.checked += 1
                
                result = None
                
                if status == 200:
                    # List bucket contents or static website
                    result = {
                        "service": "AWS S3",
                        "url": url,
                        "bucket": bucket_name,
                        "status": status,
                        "type": "listable" if "ListBucketResult" in resp.text else "public",
                        "size": len(resp.content),
                        "exposed": True
                    }
                elif status == 403:
                    # Bucket exists but restricted
                    result = {
                        "service": "AWS S3",
                        "url": url,
                        "bucket": bucket_name,
                        "status": status,
                        "type": "restricted",
                        "size": len(resp.content),
                        "exposed": False
                    }
                elif status == 404:
                    # No such bucket
                    continue
                elif status in [301, 302]:
                    # Redirect - bucket might exist elsewhere
                    result = {
                        "service": "AWS S3",
                        "url": url,
                        "bucket": bucket_name,
                        "status": status,
                        "type": "redirect",
                        "redirect_to": resp.headers.get('Location'),
                        "size": len(resp.content),
                        "exposed": False
                    }
                
                if result:
                    with self.lock:
                        self.found.append(result)
                    print(f"\n{Fore.GREEN}[{status}] AWS S3: {url}{Style.RESET_ALL}")
                    print(f"    {Fore.CYAN}Bucket: {bucket_name} | Type: {result['type']}{Style.RESET_ALL}")
                    return True
                    
            except requests.exceptions.Timeout:
                if self.verbose:
                    with self.lock:
                        print(f"{Fore.YELLOW}[TIMEOUT] S3: {url}{Style.RESET_ALL}")
            except requests.exceptions.ConnectionError:
                if self.verbose:
                    with self.lock:
                        print(f"{Fore.YELLOW}[CONNERR] S3: {url}{Style.RESET_ALL}")
            except Exception as e:
                if self.verbose:
                    with self.lock:
                        print(f"{Fore.RED}[ERROR] S3: {url} - {e}{Style.RESET_ALL}")
        
        return False
    
    def _check_azure_blob(self, container_name):
        """Check Azure Blob Storage container existence"""
        endpoints = [
            f"https://{container_name}.blob.core.windows.net",
            f"https://{container_name}.blob.core.windows.net/public",
            f"https://{container_name}.blob.core.windows.net/container",
            f"https://{container_name}.blob.core.windows.net/data",
            f"https://{container_name}.blob.core.windows.net/uploads",
            f"https://{container_name}.blob.core.windows.net/assets",
        ]
        
        for url in endpoints:
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                status = resp.status_code
                
                with self.lock:
                    self.checked += 1
                
                result = None
                
                if status == 200:
                    result = {
                        "service": "Azure Blob",
                        "url": url,
                        "container": container_name,
                        "status": status,
                        "type": "listable",
                        "size": len(resp.content),
                        "exposed": True
                    }
                elif status == 404:
                    # Check for specific error message indicating container vs account
                    if "ContainerNotFound" in resp.text:
                        continue
                    elif "ResourceNotFound" in resp.text:
                        continue
                elif status == 403:
                    result = {
                        "service": "Azure Blob",
                        "url": url,
                        "container": container_name,
                        "status": status,
                        "type": "restricted",
                        "size": len(resp.content),
                        "exposed": False
                    }
                elif status == 400 and "InvalidUri" not in resp.text:
                    # Sometimes 400 with valid container name
                    result = {
                        "service": "Azure Blob",
                        "url": url,
                        "container": container_name,
                        "status": status,
                        "type": "unknown",
                        "size": len(resp.content),
                        "exposed": False
                    }
                
                if result:
                    with self.lock:
                        self.found.append(result)
                    print(f"\n{Fore.GREEN}[{status}] Azure Blob: {url}{Style.RESET_ALL}")
                    print(f"    {Fore.CYAN}Container: {container_name} | Type: {result['type']}{Style.RESET_ALL}")
                    return True
                    
            except requests.exceptions.Timeout:
                if self.verbose:
                    with self.lock:
                        print(f"{Fore.YELLOW}[TIMEOUT] Azure: {url}{Style.RESET_ALL}")
            except requests.exceptions.ConnectionError:
                if self.verbose:
                    with self.lock:
                        print(f"{Fore.YELLOW}[CONNERR] Azure: {url}{Style.RESET_ALL}")
            except Exception as e:
                if self.verbose:
                    with self.lock:
                        print(f"{Fore.RED}[ERROR] Azure: {url} - {e}{Style.RESET_ALL}")
        
        return False
    
    def _check_gcp_storage(self, bucket_name):
        """Check Google Cloud Storage bucket existence"""
        endpoints = [
            f"https://storage.googleapis.com/{bucket_name}",
            f"https://{bucket_name}.storage.googleapis.com",
            f"https://storage.cloud.google.com/{bucket_name}",
        ]
        
        for url in endpoints:
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                status = resp.status_code
                
                with self.lock:
                    self.checked += 1
                
                result = None
                
                if status == 200:
                    # Check if it's actually a bucket listing
                    is_bucket = "ListBucketResult" in resp.text or "xmlns" in resp.text
                    result = {
                        "service": "GCP Storage",
                        "url": url,
                        "bucket": bucket_name,
                        "status": status,
                        "type": "listable" if is_bucket else "public",
                        "size": len(resp.content),
                        "exposed": True
                    }
                elif status == 403:
                    result = {
                        "service": "GCP Storage",
                        "url": url,
                        "bucket": bucket_name,
                        "status": status,
                        "type": "restricted",
                        "size": len(resp.content),
                        "exposed": False
                    }
                elif status == 404:
                    continue
                
                if result:
                    with self.lock:
                        self.found.append(result)
                    print(f"\n{Fore.GREEN}[{status}] GCP Storage: {url}{Style.RESET_ALL}")
                    print(f"    {Fore.CYAN}Bucket: {bucket_name} | Type: {result['type']}{Style.RESET_ALL}")
                    return True
                    
            except requests.exceptions.Timeout:
                if self.verbose:
                    with self.lock:
                        print(f"{Fore.YELLOW}[TIMEOUT] GCP: {url}{Style.RESET_ALL}")
            except requests.exceptions.ConnectionError:
                if self.verbose:
                    with self.lock:
                        print(f"{Fore.YELLOW}[CONNERR] GCP: {url}{Style.RESET_ALL}")
            except Exception as e:
                if self.verbose:
                    with self.lock:
                        print(f"{Fore.RED}[ERROR] GCP: {url} - {e}{Style.RESET_ALL}")
        
        return False
    
    def _check_public_dumps(self):
        """Check public breach databases and certificate transparency for cloud URLs"""
        print(f"\n{Fore.CYAN}[*] Checking certificate transparency logs...{Style.RESET_ALL}")
        
        try:
            # crt.sh search for subdomains
            domain = re.sub(r'https?://', '', self.target).strip('/')
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = self.session.get(url, timeout=30)
            
            if resp.status_code == 200:
                data = resp.json()
                subdomains = set()
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip()
                        if sub and '*' not in sub:
                            subdomains.add(sub)
                
                # Look for S3/Azure/GCP patterns in subdomains
                cloud_patterns = []
                for sub in subdomains:
                    if 's3' in sub or 'amazonaws' in sub:
                        cloud_patterns.append(("AWS S3 (cert)", sub))
                    elif 'blob.core.windows' in sub:
                        cloud_patterns.append(("Azure Blob (cert)", sub))
                    elif 'storage.googleapis' in sub:
                        cloud_patterns.append(("GCP Storage (cert)", sub))
                
                if cloud_patterns:
                    print(f"{Fore.GREEN}[+] Found {len(cloud_patterns)} cloud references in certificates:{Style.RESET_ALL}")
                    for service, pattern in cloud_patterns:
                        print(f"    {Fore.YELLOW}{service}: {pattern}{Style.RESET_ALL}")
                        self.found.append({
                            "service": service,
                            "url": f"https://{pattern}",
                            "source": "certificate_transparency",
                            "exposed": True
                        })
                else:
                    print(f"{Fore.YELLOW}[!] No cloud references found in certificates{Style.RESET_ALL}")
                    
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] Certificate check failed: {e}{Style.RESET_ALL}")
    
    def scan(self):
        print(f"\n{Fore.CYAN}[*] Starting cloud storage reconnaissance{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target: {self.target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Services: {', '.join(self.services).upper()}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Threads: {self.threads}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop early{Style.RESET_ALL}\n")
        
        # Generate bucket/container names
        names = self._generate_bucket_names()
        print(f"{Fore.CYAN}[*] Generated {len(names)} bucket/container name permutations{Style.RESET_ALL}")
        
        # Build check list based on services
        checks = []
        for name in names:
            if 'aws' in self.services:
                checks.append(('aws', name))
            if 'azure' in self.services:
                checks.append(('azure', name))
            if 'gcp' in self.services:
                checks.append(('gcp', name))
        
        self.total = len(checks)
        print(f"{Fore.CYAN}[*] Total checks: {self.total}{Style.RESET_ALL}\n")
        
        start_time = time.time()
        
        # Certificate transparency check
        self._check_public_dumps()
        
        # Run threaded checks
        try:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                for service, name in checks:
                    if service == 'aws':
                        executor.submit(self._check_aws_s3, name)
                    elif service == 'azure':
                        executor.submit(self._check_azure_blob, name)
                    elif service == 'gcp':
                        executor.submit(self._check_gcp_storage, name)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        
        elapsed = time.time() - start_time
        
        print(f"\n{Fore.CYAN}[*] Scan completed in {elapsed:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Checked: {self.checked}/{self.total}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[*] Cloud resources found: {len(self.found)}{Style.RESET_ALL}")
        
        if self.found:
            print(f"\n{Fore.GREEN}[+] Results:{Style.RESET_ALL}")
            for item in self.found:
                status_color = Fore.GREEN if item.get('exposed') else Fore.YELLOW
                print(f"  {status_color}[{item['service']}] {item['url']}{Style.RESET_ALL}")
        
        self._save_results(elapsed)
    
    def _save_results(self, elapsed):
        if not self.output_file:
            clean_target = re.sub(r'[^a-zA-Z0-9]', '_', self.target)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_file = f"cloudsniper_results_{clean_target}_{timestamp}.txt"
        
        # Text report
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("CloudSniper Scan Report\n")
            f.write("Author: Decryptious_ on Discord / Punchborn on IG\n")
            f.write("=" * 60 + "\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Platform: {platform.system()} {platform.release()}\n")
            f.write(f"Services: {', '.join(self.services).upper()}\n")
            f.write(f"Threads: {self.threads}\n")
            f.write(f"Timeout: {self.timeout}s\n")
            f.write(f"Checked: {self.checked}\n")
            f.write(f"Found: {len(self.found)}\n")
            f.write(f"Duration: {elapsed:.2f}s\n")
            f.write("=" * 60 + "\n\n")
            
            if self.found:
                f.write("[+] DISCOVERED CLOUD RESOURCES:\n")
                for item in self.found:
                    f.write(f"\nService: {item['service']}\n")
                    f.write(f"URL: {item['url']}\n")
                    if 'bucket' in item:
                        f.write(f"Bucket/Container: {item['bucket']}\n")
                    f.write(f"Status: {item.get('status', 'N/A')}\n")
                    f.write(f"Type: {item.get('type', 'unknown')}\n")
                    f.write(f"Exposed: {item.get('exposed', False)}\n")
                    f.write(f"Size: {item.get('size', 'N/A')} bytes\n")
                    if 'source' in item:
                        f.write(f"Source: {item['source']}\n")
                    f.write("-" * 40 + "\n")
            else:
                f.write("[-] No cloud resources discovered.\n")
        
        # JSON report
        json_file = self.output_file.replace('.txt', '.json')
        report = {
            "tool": "CloudSniper",
            "author": "Decryptious_ on Discord / Punchborn on IG",
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "platform": f"{platform.system()} {platform.release()}",
            "config": {
                "threads": self.threads,
                "timeout": self.timeout,
                "services": self.services
            },
            "statistics": {
                "checked": self.checked,
                "found": len(self.found),
                "duration_seconds": round(elapsed, 2)
            },
            "results": self.found
        }
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n{Fore.GREEN}[+] Text report saved: {self.output_file}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] JSON report saved: {json_file}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(
        description="CloudSniper - Cloud storage reconnaissance tool",
        epilog="Example: python3 cloudsniper.py -u example.com -s aws azure"
    )
    parser.add_argument("-u", "--url", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-s", "--services", nargs='+', choices=['aws', 'azure', 'gcp', 'all'],
                       default=['all'], help="Services to check (default: all)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads (default: 20)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("-o", "--output", help="Output file name")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (show errors/timeouts)")
    parser.add_argument("--no-banner", action="store_true", help="Hide startup banner")
    
    args = parser.parse_args()
    
    if not args.no_banner:
        print_title()
    
    # Handle 'all' service option
    services = args.services
    if 'all' in services:
        services = ['aws', 'azure', 'gcp']
    
    sniper = CloudSniper(
        target=args.url,
        threads=args.threads,
        timeout=args.timeout,
        output=args.output,
        verbose=args.verbose,
        services=services
    )
    
    sniper.scan()


if __name__ == "__main__":
    main()