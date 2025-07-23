#!/usr/bin/env python3
"""
Technology Fingerprinting Agent
Part of Modular Automated Reconnaissance System

This agent detects technologies used by live domains using multiple pip-installable modules.
Compatible with Python 3.12 and designed for integration with LangGraph workflows.
"""
from langchain_core.tools import tool

import asyncio
import aiohttp
import json
import re
import logging
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, asdict
from urllib.parse import urljoin, urlparse
import builtwith
from bs4 import BeautifulSoup
import requests
from concurrent.futures import ThreadPoolExecutor
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class TechnologyResult:
    """Data class to store technology detection results for a domain"""
    domain: str
    url: str
    status_code: int
    technologies: Dict[str, List[str]]
    headers: Dict[str, str]
    meta_tags: Dict[str, str]
    cookies: List[str]
    response_time: float
    error: Optional[str] = None

class TechnologyFingerprinter:
    """
    Advanced Technology Fingerprinting Agent using multiple detection methods
    """
    
    def __init__(self, timeout: int = 10, max_workers: int = 10, user_agent: str = None):
        self.timeout = timeout
        self.max_workers = max_workers
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        # Technology patterns for header-based detection
        self.header_patterns = {
            'Server': {
                'Apache': [r'Apache', r'Apache/[\d.]+'],
                'Nginx': [r'nginx', r'nginx/[\d.]+'],
                'IIS': [r'Microsoft-IIS', r'IIS/[\d.]+'],
                'Cloudflare': [r'cloudflare'],
                'LiteSpeed': [r'LiteSpeed'],
                'OpenResty': [r'openresty']
            },
            'X-Powered-By': {
                'PHP': [r'PHP', r'PHP/[\d.]+'],
                'ASP.NET': [r'ASP\.NET'],
                'Express': [r'Express'],
                'Django': [r'Django'],
                'Flask': [r'Flask']
            },
            'X-Generator': {
                'WordPress': [r'WordPress', r'WordPress [\d.]+'],
                'Drupal': [r'Drupal', r'Drupal [\d.]+'],
                'Joomla': [r'Joomla']
            }
        }
        
        # Content-based technology patterns
        self.content_patterns = {
            'WordPress': [
                r'/wp-content/',
                r'/wp-includes/',
                r'wp-json',
                r'wordpress',
                r'<meta name="generator" content="WordPress'
            ],
            'Drupal': [
                r'/sites/default/files/',
                r'Drupal.settings',
                r'/misc/drupal.js',
                r'<meta name="generator" content="Drupal'
            ],
            'Joomla': [
                r'/media/system/',
                r'/templates/',
                r'Joomla',
                r'<meta name="generator" content="Joomla'
            ],
            'React': [
                r'react',
                r'React',
                r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
                r'react-dom'
            ],
            'Angular': [
                r'ng-version',
                r'angular',
                r'Angular',
                r'ng-app'
            ],
            'Vue.js': [
                r'Vue\.js',
                r'vue\.js',
                r'__vue__',
                r'v-if',
                r'v-for'
            ],
            'jQuery': [
                r'jquery',
                r'jQuery',
                r'\$\(document\)\.ready'
            ],
            'Bootstrap': [
                r'bootstrap',
                r'Bootstrap',
                r'btn-primary',
                r'container-fluid'
            ]
        }

    async def fingerprint_domains(self, domains: List[str]) -> List[TechnologyResult]:
        """
        Main method to fingerprint technologies for a list of domains
        
        Args:
            domains: List of live domain names
            
        Returns:
            List of TechnologyResult objects
        """
        logger.info(f"Starting technology fingerprinting for {len(domains)} domains")
        
        # Prepare URLs (ensure they have protocol)
        urls = []
        for domain in domains:
            if not domain.startswith(('http://', 'https://')):
                # Try HTTPS first, then HTTP
                urls.extend([f"https://{domain}", f"http://{domain}"])
            else:
                urls.append(domain)
        
        # Remove duplicates while preserving order
        urls = list(dict.fromkeys(urls))
        
        results = []
        
        # Use asyncio for concurrent processing
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={'User-Agent': self.user_agent}
        ) as session:
            
            # Process domains in batches to avoid overwhelming targets
            batch_size = min(self.max_workers, 5)
            for i in range(0, len(urls), batch_size):
                batch = urls[i:i + batch_size]
                batch_tasks = [self._fingerprint_single_url(session, url) for url in batch]
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, TechnologyResult):
                        results.append(result)
                    elif isinstance(result, Exception):
                        logger.error(f"Error in batch processing: {result}")
                
                # Small delay between batches to be respectful
                if i + batch_size < len(urls):
                    await asyncio.sleep(1)
        
        # Remove duplicate domains (keep HTTPS version if both exist)
        unique_results = self._deduplicate_results(results)
        
        logger.info(f"Technology fingerprinting completed for {len(unique_results)} domains")
        return unique_results

    async def _fingerprint_single_url(self, session: aiohttp.ClientSession, url: str) -> TechnologyResult:
        """Fingerprint a single URL"""
        start_time = time.time()
        domain = urlparse(url).netloc
        
        try:
            async with session.get(url, ssl=False, allow_redirects=True) as response:
                content = await response.text(errors='ignore')
                response_time = time.time() - start_time
                
                # Extract headers
                headers = dict(response.headers)
                
                # Extract cookies
                cookies = [f"{cookie.key}={cookie.value}" for cookie in response.cookies.values()]
                
                # Parse HTML for meta tags
                meta_tags = self._extract_meta_tags(content)
                
                # Detect technologies using multiple methods
                technologies = {}
                
                # Method 1: Header-based detection
                header_techs = self._detect_from_headers(headers)
                technologies.update(header_techs)
                
                # Method 2: Content-based detection
                content_techs = self._detect_from_content(content)
                technologies.update(content_techs)
                
                # Method 3: BuiltWith detection (external service)
                try:
                    builtwith_techs = self._detect_with_builtwith(domain)
                    for category, techs in builtwith_techs.items():
                        if category not in technologies:
                            technologies[category] = []
                        technologies[category].extend(techs)
                        technologies[category] = list(set(technologies[category]))  # Remove duplicates
                except Exception as e:
                    logger.debug(f"BuiltWith detection failed for {domain}: {e}")
                
                return TechnologyResult(
                    domain=domain,
                    url=url,
                    status_code=response.status,
                    technologies=technologies,
                    headers=headers,
                    meta_tags=meta_tags,
                    cookies=cookies,
                    response_time=response_time
                )
                
        except asyncio.TimeoutError:
            return TechnologyResult(
                domain=domain,
                url=url,
                status_code=0,
                technologies={},
                headers={},
                meta_tags={},
                cookies=[],
                response_time=time.time() - start_time,
                error="Timeout"
            )
        except Exception as e:
            return TechnologyResult(
                domain=domain,
                url=url,
                status_code=0,
                technologies={},
                headers={},
                meta_tags={},
                cookies=[],
                response_time=time.time() - start_time,
                error=str(e)
            )

    def _extract_meta_tags(self, content: str) -> Dict[str, str]:
        """Extract meta tags from HTML content"""
        meta_tags = {}
        try:
            soup = BeautifulSoup(content, 'html.parser')
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property') or meta.get('http-equiv')
                content_attr = meta.get('content')
                if name and content_attr:
                    meta_tags[name.lower()] = content_attr
        except Exception as e:
            logger.debug(f"Error parsing HTML: {e}")
        return meta_tags

    def _detect_from_headers(self, headers: Dict[str, str]) -> Dict[str, List[str]]:
        """Detect technologies from HTTP headers"""
        technologies = {}
        
        for header_name, patterns in self.header_patterns.items():
            header_value = headers.get(header_name, '')
            if header_value:
                for tech_name, tech_patterns in patterns.items():
                    for pattern in tech_patterns:
                        if re.search(pattern, header_value, re.IGNORECASE):
                            category = 'Web Servers' if header_name == 'Server' else 'Programming Languages'
                            if category not in technologies:
                                technologies[category] = []
                            technologies[category].append(tech_name)
                            break
        
        return technologies

    def _detect_from_content(self, content: str) -> Dict[str, List[str]]:
        """Detect technologies from page content"""
        technologies = {}
        
        for tech_name, patterns in self.content_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    category = self._categorize_technology(tech_name)
                    if category not in technologies:
                        technologies[category] = []
                    if tech_name not in technologies[category]:
                        technologies[category].append(tech_name)
                    break
        
        return technologies

    def _detect_with_builtwith(self, domain: str) -> Dict[str, List[str]]:
        """Use BuiltWith library for technology detection"""
        try:
            result = builtwith.parse(f"http://{domain}")
            # Clean up the result format
            cleaned_result = {}
            for category, techs in result.items():
                if techs:  # Only include non-empty categories
                    cleaned_result[category] = [tech.strip() for tech in techs if tech.strip()]
            return cleaned_result
        except Exception as e:
            logger.debug(f"BuiltWith error for {domain}: {e}")
            return {}

    def _categorize_technology(self, tech_name: str) -> str:
        """Categorize technology by name"""
        cms_techs = ['WordPress', 'Drupal', 'Joomla']
        js_frameworks = ['React', 'Angular', 'Vue.js', 'jQuery']
        css_frameworks = ['Bootstrap']
        
        if tech_name in cms_techs:
            return 'Content Management Systems'
        elif tech_name in js_frameworks:
            return 'JavaScript Frameworks'
        elif tech_name in css_frameworks:
            return 'CSS Frameworks'
        else:
            return 'Other'

    def _deduplicate_results(self, results: List[TechnologyResult]) -> List[TechnologyResult]:
        """Remove duplicate domains, preferring HTTPS and successful responses"""
        domain_results = {}
        
        for result in results:
            domain = result.domain
            
            if domain not in domain_results:
                domain_results[domain] = result
            else:
                existing = domain_results[domain]
                # Prefer HTTPS over HTTP
                if result.url.startswith('https://') and existing.url.startswith('http://'):
                    domain_results[domain] = result
                # Prefer successful responses
                elif result.status_code == 200 and existing.status_code != 200:
                    domain_results[domain] = result
                # Prefer results with more technologies detected
                elif len(result.technologies) > len(existing.technologies):
                    domain_results[domain] = result
        
        return list(domain_results.values())

    def export_results(self, results: List[TechnologyResult], format: str = 'json') -> str:
        """Export results in different formats"""
        if format.lower() == 'json':
            return json.dumps([asdict(result) for result in results], indent=2, default=str)
        elif format.lower() == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            if results:
                fieldnames = ['domain', 'url', 'status_code', 'technologies', 'response_time', 'error']
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in results:
                    row = asdict(result)
                    row['technologies'] = json.dumps(row['technologies'])
                    row['headers'] = json.dumps(row['headers'])
                    row['meta_tags'] = json.dumps(row['meta_tags'])
                    row['cookies'] = json.dumps(row['cookies'])
                    writer.writerow({k: v for k, v in row.items() if k in fieldnames})
            
            return output.getvalue()
        else:
            raise ValueError("Supported formats: 'json', 'csv'")

# FIXED: Convert async function to sync wrapper
@tool
def technology_fingerprinter(test_domains: List[str]) -> str:
    """
    Tool Name: technology_fingerprinter

    Description:
    This tool performs technology fingerprinting on a list of live domain URLs.
    It detects the underlying web technologies, HTTP headers, and status codes for each domain. The output is returned
    as a structured JSON list where each item contains detailed information about the scanned domain.

    Input:
    - test_domains (List[str]): A list of live domain URLs (e.g., ["https://example.com", "http://site.org"]).
    Each domain must include the scheme ("http://" or "https://").

    Output:
    - str: A structured JSON string where each element contains:
        - domain (str): The root domain scanned.
        - url (str): The full URL that was analyzed.
        - status_code (int): The HTTP status code returned by the server.
        - technologies (Dict[str, List[str]]): A categorized dictionary of detected technologies.
        - headers (Dict[str, str]): Response headers from the server.
    """
    
    async def run_fingerprinting():
        # Initialize the fingerprinter
        fingerprinter = TechnologyFingerprinter(timeout=15, max_workers=5)
        
        # Run fingerprinting
        results = await fingerprinter.fingerprint_domains(test_domains)
        
        # Display results
        print("\n" + "="*80)
        print("TECHNOLOGY FINGERPRINTING RESULTS")
        print("="*80)
        
        # for result in results:
        #     print(f"\nDomain: {result.domain}")
        #     print(f"URL: {result.url}")
        #     print(f"Status: {result.status_code}")
        #     print(f"Response Time: {result.response_time:.2f}s")
            
        #     if result.error:
        #         print(f"Error: {result.error}")
        #     else:
        #         print("Technologies Detected:")
        #         for category, techs in result.technologies.items():
        #             if techs:
        #                 print(f"  {category}: {', '.join(techs)}")
                
        #         if result.headers.get('Server'):
        #             print(f"Server: {result.headers['Server']}")
                
        #         if result.meta_tags.get('generator'):
        #             print(f"Generator: {result.meta_tags['generator']}")
            
        #     print("-" * 40)
        
        # Export results
        json_output = fingerprinter.export_results(results, 'json')
        return json_output[:500] if len(json_output) > 500 else json_output
    
    # Run the async function in the current event loop or create a new one
    try:
        loop = asyncio.get_running_loop()
        # If there's already a running loop, we need to use a different approach
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(asyncio.run, run_fingerprinting())
            return future.result()
    except RuntimeError:
        # No running loop, so we can use asyncio.run directly
        return asyncio.run(run_fingerprinting())
