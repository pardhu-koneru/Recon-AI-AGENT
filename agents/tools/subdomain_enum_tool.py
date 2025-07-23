"""
tools/subdomain_enum_tool.py
Advanced Subdomain Enumeration Tool for LangChain Agents
Replaces sublist3r with pip-installable tools and agentic AI capabilities
"""

import asyncio
import aiohttp
import requests
import dns.resolver
import dns.exception
import ssl
import socket
import re
import time
import json
from typing import Set, List, Dict, Optional, Any
from urllib.parse import urlparse
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from datetime import datetime
from langchain.tools import tool
from langchain_core.tools import ToolException

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SubdomainResult:
    """Data structure for subdomain discovery results"""
    subdomain: str
    source: str
    is_live: bool = False
    ip_address: Optional[str] = None
    status_code: Optional[int] = None
    title: Optional[str] = None
    technology: Optional[str] = None
    ssl_valid: bool = False
    response_time: Optional[float] = None

class SubdomainEnumerator:
    """
    Advanced Subdomain Enumeration Engine
    Designed for integration with LangChain agents
    """
    
    def __init__(self, target_domain: str, timeout: int = 8, max_workers: int = 30):
        self.target_domain = target_domain.lower().strip()
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = None
        self.discovered_subdomains: Set[str] = set()
        
        # Enhanced subdomain wordlist for better coverage
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'admin', 'test', 'dev',
            'staging', 'api', 'app', 'beta', 'mobile', 'cdn', 'static', 'assets', 'blog',
            'shop', 'store', 'forum', 'chat', 'support', 'help', 'docs', 'wiki', 'news',
            'portal', 'vpn', 'secure', 'ssl', 'mx', 'mx1', 'mx2', 'imap', 'pop3', 'webmin',
            'phpmyadmin', 'mysql', 'database', 'db', 'backup', 'files', 'upload', 'download',
            'git', 'svn', 'jenkins', 'ci', 'demo', 'preview', 'old', 'new', 'v1', 'v2',
            'img', 'images', 'video', 'media', 'js', 'css', 'status', 'monitor', 'dashboard',
            'login', 'auth', 'sso', 'identity', 'ldap', 'ad', 'dc', 'exchange', 'outlook',
            'office', 'sharepoint', 'teams', 'azure', 'aws', 'cloud', 'k8s', 'docker',
            'registry', 'artifactory', 'nexus', 'sonar', 'grafana', 'prometheus', 'elk',
            'kibana', 'redis', 'mongo', 'postgres', 'oracle', 'mssql', 'mariadb'
        ]
    
    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(
            limit=self.max_workers,
            limit_per_host=10,
            ttl_dns_cache=300,
            use_dns_cache=True,
            ssl=False
        )
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def dns_bruteforce(self) -> Dict[str, List[str]]:
        """
        Intelligent DNS brute force with categorized results
        """
        logger.info(f"🔍 Starting DNS brute force for {self.target_domain}")
        results = {
            'found_subdomains': [],
            'method': 'dns_bruteforce',
            'total_checked': len(self.common_subdomains)
        }
        
        def check_subdomain(subdomain: str) -> Optional[Dict[str, str]]:
            full_domain = f"{subdomain}.{self.target_domain}"
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                
                # Try A record first
                try:
                    answers = resolver.resolve(full_domain, 'A')
                    if answers:
                        return {
                            'subdomain': full_domain,
                            'ip': str(answers[0]),
                            'record_type': 'A'
                        }
                except dns.resolver.NXDOMAIN:
                    pass
                except dns.resolver.NoAnswer:
                    # Try CNAME if A record fails
                    try:
                        answers = resolver.resolve(full_domain, 'CNAME')
                        if answers:
                            return {
                                'subdomain': full_domain,
                                'cname': str(answers[0]),
                                'record_type': 'CNAME'
                            }
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        pass
                        
            except (dns.exception.Timeout, dns.exception.DNSException):
                pass
            return None
        
        # Parallel DNS queries
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_subdomain = {
                executor.submit(check_subdomain, sub): sub 
                for sub in self.common_subdomains
            }
            
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    results['found_subdomains'].append(result)
                    logger.info(f"✅ DNS: Found {result['subdomain']}")
        
        return results
    
    def certificate_transparency(self) -> Dict[str, Any]:
        """
        Enhanced Certificate Transparency search with multiple sources
        """
        logger.info(f"🔍 Searching Certificate Transparency logs for {self.target_domain}")
        results = {
            'found_subdomains': [],
            'method': 'certificate_transparency',
            'sources_tried': []
        }
        
        # Multiple CT log sources for better coverage
        ct_sources = [
            {
                'name': 'crt.sh',
                'url': f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            },
            {
                'name': 'crt.sh_exact',
                'url': f"https://crt.sh/?q={self.target_domain}&output=json"
            }
        ]
        
        for source in ct_sources:
            try:
                results['sources_tried'].append(source['name'])
                response = requests.get(source['url'], timeout=self.timeout)
                
                if response.status_code == 200:
                    certificates = response.json()
                    
                    for cert in certificates:
                        if 'name_value' in cert:
                            names = cert['name_value'].split('\n')
                            for name in names:
                                name = name.strip().lower()
                                if name.endswith(f".{self.target_domain}") or name == self.target_domain:
                                    if not name.startswith('*.') and name not in [r['subdomain'] for r in results['found_subdomains']]:
                                        results['found_subdomains'].append({
                                            'subdomain': name,
                                            'source': source['name'],
                                            'issuer': cert.get('issuer_name', 'Unknown')
                                        })
                                        logger.info(f"✅ CT: Found {name} from {source['name']}")
                    
                    if results['found_subdomains']:
                        break  # Stop if we found subdomains
                        
            except requests.RequestException as e:
                logger.warning(f"❌ CT source {source['name']} failed: {e}")
                continue
        
        return results
    
    def api_enumeration(self) -> Dict[str, Any]:
        """
        Multiple API-based subdomain discovery
        """
        logger.info(f"🔍 Querying multiple APIs for {self.target_domain}")
        results = {
            'found_subdomains': [],
            'method': 'api_enumeration',
            'apis_used': []
        }
        
        # HackerTarget API
        try:
            results['apis_used'].append('hackertarget')
            api_url = f"https://api.hackertarget.com/hostsearch/?q={self.target_domain}"
            response = requests.get(api_url, timeout=self.timeout)
            
            if response.status_code == 200 and "error" not in response.text.lower():
                lines = response.text.strip().split('\n')
                for line in lines:
                    if ',' in line and not line.startswith('API'):
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain.endswith(f".{self.target_domain}") or subdomain == self.target_domain:
                            results['found_subdomains'].append({
                                'subdomain': subdomain,
                                'source': 'hackertarget'
                            })
                            logger.info(f"✅ HackerTarget: Found {subdomain}")
        except requests.RequestException as e:
            logger.warning(f"❌ HackerTarget API failed: {e}")
        
        # ThreatCrowd API
        try:
            results['apis_used'].append('threatcrowd')
            api_url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.target_domain}"
            response = requests.get(api_url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                if 'subdomains' in data and data['subdomains']:
                    for subdomain in data['subdomains']:
                        subdomain = subdomain.lower().strip()
                        if subdomain.endswith(f".{self.target_domain}") or subdomain == self.target_domain:
                            results['found_subdomains'].append({
                                'subdomain': subdomain,
                                'source': 'threatcrowd'
                            })
                            logger.info(f"✅ ThreatCrowd: Found {subdomain}")
        except (requests.RequestException, json.JSONDecodeError) as e:
            logger.warning(f"❌ ThreatCrowd API failed: {e}")
        
        return results
    
    async def verify_and_analyze(self, subdomains: List[str]) -> List[SubdomainResult]:
        """
        Verify subdomains and gather detailed information
        """
        logger.info(f"🔍 Verifying {len(subdomains)} subdomains...")
        
        async def check_subdomain(subdomain: str) -> SubdomainResult:
            result = SubdomainResult(subdomain=subdomain, source="verification")
            start_time = time.time()
            
            try:
                # DNS resolution
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 3
                    answers = resolver.resolve(subdomain, 'A')
                    result.ip_address = str(answers[0])
                except dns.exception.DNSException:
                    return result
                
                # HTTP/HTTPS verification
                protocols = ['https', 'http']
                for protocol in protocols:
                    try:
                        url = f"{protocol}://{subdomain}"
                        async with self.session.get(url, ssl=False, allow_redirects=True) as response:
                            result.is_live = True
                            result.status_code = response.status
                            result.response_time = time.time() - start_time
                            
                            # Extract page title
                            try:
                                content = await response.text()
                                title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                                if title_match:
                                    result.title = title_match.group(1).strip()[:100]  # Limit title length
                                
                                # Basic technology detection
                                content_lower = content.lower()
                                if 'wordpress' in content_lower or 'wp-content' in content_lower:
                                    result.technology = 'WordPress'
                                elif 'drupal' in content_lower:
                                    result.technology = 'Drupal'
                                elif 'joomla' in content_lower:
                                    result.technology = 'Joomla'
                                elif 'apache' in response.headers.get('server', '').lower():
                                    result.technology = 'Apache'
                                elif 'nginx' in response.headers.get('server', '').lower():
                                    result.technology = 'Nginx'
                                elif 'iis' in response.headers.get('server', '').lower():
                                    result.technology = 'IIS'
                                    
                            except Exception:
                                pass
                            
                            # SSL validation for HTTPS
                            if protocol == 'https':
                                try:
                                    context = ssl.create_default_context()
                                    context.check_hostname = False
                                    context.verify_mode = ssl.CERT_NONE
                                    
                                    with socket.create_connection((subdomain, 443), timeout=3) as sock:
                                        with context.wrap_socket(sock, server_hostname=subdomain) as ssock:
                                            cert = ssock.getpeercert()
                                            if cert:
                                                result.ssl_valid = True
                                except Exception:
                                    pass
                            
                            break  # Found working protocol
                            
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue
                        
            except Exception as e:
                logger.debug(f"Error verifying {subdomain}: {e}")
            
            return result
        
        # Create verification tasks
        tasks = [check_subdomain(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful results
        verified_results = [r for r in results if isinstance(r, SubdomainResult)]
        
        return verified_results
    
    async def run_comprehensive_scan(self) -> Dict[str, Any]:
        """
        Run comprehensive subdomain enumeration with all methods
        """
        logger.info(f"🚀 Starting comprehensive subdomain scan for {self.target_domain}")
        scan_start = time.time()
        
        all_subdomains = set()
        scan_results = {
            'target_domain': self.target_domain,
            'scan_timestamp': datetime.now().isoformat(),
            'methods_used': [],
            'raw_results': {},
            'summary': {},
            'live_subdomains': []
        }
        
        # DNS Brute Force
        try:
            dns_results = self.dns_bruteforce()
            scan_results['methods_used'].append('dns_bruteforce')
            scan_results['raw_results']['dns_bruteforce'] = dns_results
            
            for result in dns_results['found_subdomains']:
                all_subdomains.add(result['subdomain'])
        except Exception as e:
            logger.error(f"DNS brute force failed: {e}")
        
        # Certificate Transparency
        try:
            ct_results = self.certificate_transparency()
            scan_results['methods_used'].append('certificate_transparency')
            scan_results['raw_results']['certificate_transparency'] = ct_results
            
            for result in ct_results['found_subdomains']:
                all_subdomains.add(result['subdomain'])
        except Exception as e:
            logger.error(f"Certificate transparency failed: {e}")
        
        # API Enumeration
        try:
            api_results = self.api_enumeration()
            scan_results['methods_used'].append('api_enumeration')
            scan_results['raw_results']['api_enumeration'] = api_results
            
            for result in api_results['found_subdomains']:
                all_subdomains.add(result['subdomain'])
        except Exception as e:
            logger.error(f"API enumeration failed: {e}")
        
        # Add main domain
        all_subdomains.add(self.target_domain)
        
        logger.info(f"📊 Discovered {len(all_subdomains)} unique subdomains")
        
        # Verify live subdomains
        try:
            verified_results = await self.verify_and_analyze(list(all_subdomains))
            live_results = [r for r in verified_results if r.is_live]
            
            scan_results['live_subdomains'] = [asdict(r) for r in verified_results]
            scan_results['summary'] = {
                'total_discovered': len(all_subdomains),
                'total_verified': len(verified_results),
                'live_subdomains': len(live_results),
                'scan_duration': round(time.time() - scan_start, 2)
            }
            
            logger.info(f"✅ Scan complete! {len(live_results)} live subdomains found in {scan_results['summary']['scan_duration']} seconds")
            
        except Exception as e:
            logger.error(f"Verification failed: {e}")
            scan_results['error'] = str(e)
        
        return scan_results

# LangChain Tool Definition
@tool
def subdomain_scan(domain: str) -> str:
    """
    Comprehensive subdomain enumeration tool for reconnaissance.
    
    This tool performs advanced subdomain discovery using multiple methods:
    - DNS brute force with comprehensive wordlist
    - Certificate Transparency log analysis
    - Multiple API sources (HackerTarget, ThreatCrowd)
    - Live subdomain verification with detailed analysis
    
    Args:
        domain: Target domain to enumerate subdomains for (e.g., "example.com")
    
    Returns:
        JSON string containing comprehensive subdomain enumeration results
    """
    try:
        # Input validation
        if not domain or not isinstance(domain, str):
            raise ToolException("Domain parameter is required and must be a string")
        
        # Clean domain input
        domain = domain.strip().lower()
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).netloc
        
        # Remove www prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Basic domain validation
        if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
            raise ToolException(f"Invalid domain format: {domain}")
        
        # Run the enumeration
        async def run_scan():
            async with SubdomainEnumerator(domain, timeout=10, max_workers=30) as enumerator:
                return await enumerator.run_comprehensive_scan()
        
        results = asyncio.run(run_scan())
        
        # Format results for agent consumption
        if results['summary']['live_subdomains'] > 0:
            # Create a concise summary for the agent
            live_subs = [r for r in results['live_subdomains'] if r['is_live']]
            
            summary = f"""
SUBDOMAIN ENUMERATION RESULTS FOR {domain.upper()}:

📊 SUMMARY:
- Total Discovered: {results['summary']['total_discovered']}
- Live Subdomains: {results['summary']['live_subdomains']}
- Scan Duration: {results['summary']['scan_duration']}s
- Methods Used: {', '.join(results['methods_used'])}

🎯 LIVE SUBDOMAINS:
"""
            
            for sub in live_subs[:20]:  # Limit to first 20 for readability
                status = f"[{sub['status_code']}]" if sub['status_code'] else "[???]"
                ip = f"({sub['ip_address']})" if sub['ip_address'] else ""
                title = f"- {sub['title']}" if sub['title'] else ""
                tech = f"[{sub['technology']}]" if sub['technology'] else ""
                ssl = "🔒" if sub['ssl_valid'] else ""
                
                summary += f"  {status} {ssl} {sub['subdomain']} {ip} {tech} {title}\n"
            
            if len(live_subs) > 20:
                summary += f"  ... and {len(live_subs) - 20} more subdomains\n"
            
            summary += f"\n📋 Full results contain {len(results['live_subdomains'])} total entries with detailed analysis."
            
            return summary
        else:
            return f"No live subdomains found for {domain}. This could indicate the domain is not active or well-protected."
            
    except Exception as e:
        error_msg = f"Subdomain enumeration failed for {domain}: {str(e)}"
        logger.error(error_msg)
        raise ToolException(error_msg)

# Alternative tool for just getting the list
@tool
def subdomain_list(domain: str) -> str:
    """
    Get a simple list of live subdomains for a domain.
    
    Args:
        domain: Target domain to enumerate subdomains for
    
    Returns:
        Comma-separated list of live subdomains
    """
    try:
        # Reuse the main scan function
        async def run_scan():
            async with SubdomainEnumerator(domain, timeout=8, max_workers=20) as enumerator:
                return await enumerator.run_comprehensive_scan()
        
        results = asyncio.run(run_scan())
        live_subs = [r['subdomain'] for r in results['live_subdomains'] if r['is_live']]
        
        return ', '.join(sorted(live_subs)) if live_subs else f"No live subdomains found for {domain}"
        
    except Exception as e:
        raise ToolException(f"Failed to get subdomain list for {domain}: {str(e)}")

# Export tools for use in agents
__all__ = ['subdomain_scan', 'subdomain_list', 'SubdomainEnumerator']