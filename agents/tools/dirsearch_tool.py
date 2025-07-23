#!/usr/bin/env python3
"""
Directory Search Tool
Part of Modular Automated Reconnaissance System

This tool performs directory enumeration on live subdomains using a comprehensive wordlist.
Compatible with Python 3.12 and designed for integration with LangGraph workflows.
"""

from langchain_core.tools import tool
import asyncio
import aiohttp
import json
import logging
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import time
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class DirectoryResult:
    """Data class to store directory search results"""
    domain: str
    url: str
    path: str
    status_code: int
    response_size: int
    response_time: float
    content_type: str
    redirect_location: Optional[str] = None
    error: Optional[str] = None

class DirectorySearcher:
    """
    Advanced Directory Search Tool using asyncio for concurrent requests
    """
    
    def __init__(self, timeout: int = 10, max_workers: int = 20, user_agent: str = None):
        self.timeout = timeout
        self.max_workers = max_workers
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        
        # Status codes to consider as "found"
        self.interesting_status_codes = {200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500, 503}

    def create_wordlist(self) -> List[str]:
        """Create a comprehensive directory/file wordlist"""
        
        # Common directories
        directories = [
            # Admin/Management
            "admin", "administrator", "administration", "admins", "admin_area", "admincp",
            "admin-console", "admin_panel", "controlpanel", "cpanel", "dashboard", "manager",
            "management", "webmaster", "sysadmin", "moderator", "wp-admin", "wp-login",
            
            # API and Services
            "api", "apis", "v1", "v2", "v3", "rest", "graphql", "soap", "rpc", "service",
            "services", "webservice", "webservices", "endpoint", "endpoints", "gateway",
            
            # Authentication
            "login", "signin", "signup", "register", "auth", "oauth", "sso", "logout",
            "password", "forgot", "reset", "recover", "activation", "verify", "2fa",
            
            # Common Web Directories
            "assets", "static", "public", "resources", "res", "media", "files", "uploads",
            "download", "downloads", "shared", "common", "lib", "libs", "library",
            "vendor", "vendors", "modules", "plugins", "extensions", "addons", "components",
            
            # Content Management
            "content", "cms", "blog", "news", "articles", "posts", "pages", "site",
            "website", "portal", "forum", "forums", "community", "wiki", "docs",
            "documentation", "help", "support", "faq", "about", "contact",
            
            # Development/Testing
            "test", "tests", "testing", "dev", "development", "staging", "beta", "alpha",
            "demo", "sandbox", "tmp", "temp", "cache", "logs", "log", "debug",
            "source", "src", "backup", "backups", "old", "archive", "archives",
            
            # Database
            "db", "database", "databases", "data", "sql", "mysql", "postgres", "mongodb",
            "redis", "phpmyadmin", "adminer", "sqlbuddy", "dbadmin",
            
            # Configuration
            "config", "configuration", "settings", "setup", "install", "installation",
            "wizard", "init", "env", "conf", "cfg", "ini",
            
            # Security
            "security", "secure", "ssl", "https", "cert", "certificates", "keys",
            "private", "protected", "restricted", "forbidden", "deny",
            
            # Monitoring
            "monitor", "monitoring", "stats", "statistics", "analytics", "metrics",
            "status", "health", "ping", "info", "version", "build",
            
            # User Areas
            "user", "users", "profile", "profiles", "account", "accounts", "member",
            "members", "client", "clients", "customer", "customers", "guest",
            
            # E-commerce
            "shop", "store", "cart", "checkout", "payment", "payments", "order",
            "orders", "invoice", "invoices", "billing", "subscription",
            
            # Mobile/App
            "mobile", "app", "apps", "android", "ios", "download", "apk",
            
            # Git/Version Control
            ".git", ".svn", ".hg", "git", "svn", "mercurial", "cvs",
            
            # Server/Infrastructure
            "server", "servers", "node", "nodes", "cluster", "load-balancer",
            "proxy", "cdn", "cache", "mail", "email", "ftp", "sftp",
            
            # Search/Browse
            "search", "browse", "explorer", "finder", "directory", "index",
            
            # Tools/Utilities
            "tools", "utilities", "util", "utils", "scripts", "bin", "exe",
            "run", "exec", "cgi-bin", "fcgi-bin",
        ]
        
        # Common files
        files = [
            # Index files
            "index", "home", "main", "default", "welcome",
            
            # Configuration files
            "config.php", "config.json", "config.xml", "config.yml", "config.yaml",
            "settings.php", "settings.json", "web.config", ".htaccess", ".htpasswd",
            "wp-config.php", "database.php", "db.php", "connection.php", "connect.php",
            ".env", ".env.local", ".env.production", ".env.development",
            
            # Common web files
            "robots.txt", "sitemap.xml", "sitemap.txt", "humans.txt", "crossdomain.xml",
            "favicon.ico", "apple-touch-icon.png", "browserconfig.xml", "manifest.json",
            
            # Admin files
            "admin.php", "administrator.php", "login.php", "signin.php", "auth.php",
            "dashboard.php", "panel.php", "cpanel.php", "controlpanel.php",
            
            # API files
            "api.php", "rest.php", "service.php", "endpoint.php", "graphql.php",
            
            # Database files
            "phpmyadmin", "adminer.php", "database.sql", "dump.sql", "backup.sql",
            "db.sql", "data.sql", "users.sql", "mysql.sql", "postgres.sql",
            
            # Backup files
            "backup.zip", "backup.tar.gz", "site.zip", "www.zip", "database.zip",
            "backup.sql", "dump.sql", "old.zip", "archive.zip",
            
            # Log files
            "error.log", "access.log", "debug.log", "app.log", "application.log",
            "system.log", "security.log", "audit.log",
            
            # Documentation
            "readme.txt", "readme.md", "changelog.txt", "changelog.md", "license.txt",
            "todo.txt", "help.txt", "install.txt", "upgrade.txt",
            
            # Common pages
            "about.php", "contact.php", "services.php", "portfolio.php", "gallery.php",
            "news.php", "blog.php", "search.php", "sitemap.php", "privacy.php",
            "terms.php", "policy.php", "disclaimer.php",
            
            # Test files
            "test.php", "test.html", "phpinfo.php", "info.php", "debug.php",
            "test.txt", "example.php", "sample.php", "demo.php",
            
            # Upload/Media files
            "upload.php", "file.php", "image.php", "photo.php", "video.php",
            "download.php", "attachment.php", "media.php",
        ]
        
        # File extensions to try
        extensions = ["", ".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".do", 
                     ".action", ".cgi", ".pl", ".py", ".rb", ".js", ".json", ".xml", 
                     ".txt", ".pdf", ".zip", ".tar.gz", ".sql", ".bak", ".old"]
        
        # Combine all paths
        wordlist = []
        
        # Add directories with trailing slash
        for directory in directories:
            wordlist.append(f"{directory}/")
        
        # Add files as-is
        wordlist.extend(files)
        
        # Add directories with common file extensions
        for directory in directories[:50]:  # Limit to avoid too many combinations
            for ext in [".php", ".html", ".htm", ".asp", ".aspx", ".jsp"]:
                wordlist.append(f"{directory}{ext}")
        
        # Add some common file names with extensions
        common_names = ["index", "admin", "login", "config", "test", "api", "home", "main"]
        for name in common_names:
            for ext in extensions:
                wordlist.append(f"{name}{ext}")
        
        # Remove duplicates and sort
        wordlist = sorted(list(set(wordlist)))
        
        logger.info(f"Created wordlist with {len(wordlist)} entries")
        return wordlist

    async def search_directories(self, domains: List[str]) -> Dict[str, Dict[str, List[str]]]:
        """
        Main method to perform directory search on multiple domains
        
        Args:
            domains: List of live domain URLs
            
        Returns:
            Dict in format: {"domain_name": {"status_code": ["url1", "url2"]}}
        """
        logger.info(f"Starting directory search for {len(domains)} domains")
        
        wordlist = self.create_wordlist()
        all_results = []
        
        # Process each domain
        for domain in domains:
            domain_results = await self._search_single_domain(domain, wordlist)
            all_results.extend(domain_results)
            
            # Small delay between domains to be respectful
            await asyncio.sleep(0.5)
        
        # Convert results to the requested format
        formatted_results = self._format_results(all_results)
        
        logger.info(f"Directory search completed for {len(domains)} domains")
        return formatted_results

    def _format_results(self, results: List[DirectoryResult]) -> Dict[str, Dict[str, List[str]]]:
        """
        Convert results to the requested format:
        {"domain_name": {"status_code": ["url1", "url2"]}}
        """
        formatted = defaultdict(lambda: defaultdict(list))
        
        for result in results:
            if result.status_code in self.interesting_status_codes and not result.error:
                domain_name = result.domain
                status_code = str(result.status_code)
                url = result.url
                
                formatted[domain_name][status_code].append(url)
        
        # Convert defaultdict to regular dict for JSON serialization
        return {domain: dict(status_dict) for domain, status_dict in formatted.items()}

    async def _search_single_domain(self, domain: str, wordlist: List[str]) -> List[DirectoryResult]:
        """Search directories for a single domain"""
        
        # Ensure domain has protocol
        if not domain.startswith(('http://', 'https://')):
            base_url = f"https://{domain}"
        else:
            base_url = domain
            
        # Extract clean domain name for the result key
        parsed_url = urlparse(base_url)
        clean_domain = parsed_url.netloc
        
        results = []
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={'User-Agent': self.user_agent},
            connector=aiohttp.TCPConnector(limit=self.max_workers, ssl=False)
        ) as session:
            
            # Create tasks for all paths
            tasks = []
            for path in wordlist:
                url = urljoin(base_url, path)
                task = self._check_single_path(session, clean_domain, url, path)
                tasks.append(task)
            
            # Process in batches to avoid overwhelming the server
            batch_size = min(self.max_workers, 20)
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i + batch_size]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, DirectoryResult) and result.status_code in self.interesting_status_codes:
                        results.append(result)
                    elif isinstance(result, Exception):
                        logger.debug(f"Error in batch processing: {result}")
                
                # Small delay between batches
                if i + batch_size < len(tasks):
                    await asyncio.sleep(0.1)
        
        logger.info(f"Found {len(results)} interesting paths for {clean_domain}")
        return results

    async def _check_single_path(self, session: aiohttp.ClientSession, domain: str, url: str, path: str) -> DirectoryResult:
        """Check a single path on a domain"""
        start_time = time.time()
        
        try:
            async with session.get(url, allow_redirects=False) as response:
                response_time = time.time() - start_time
                content_length = response.headers.get('Content-Length', '0')
                content_type = response.headers.get('Content-Type', '').split(';')[0].strip()
                redirect_location = response.headers.get('Location')
                
                try:
                    response_size = int(content_length)
                except (ValueError, TypeError):
                    # If Content-Length is not available, read a small portion to estimate size
                    try:
                        content_sample = await response.read(1024)  # Read first 1KB
                        response_size = len(content_sample)
                    except:
                        response_size = 0
                
                return DirectoryResult(
                    domain=domain,
                    url=url,
                    path=path,
                    status_code=response.status,
                    response_size=response_size,
                    response_time=response_time,
                    content_type=content_type,
                    redirect_location=redirect_location
                )
                
        except asyncio.TimeoutError:
            return DirectoryResult(
                domain=domain,
                url=url,
                path=path,
                status_code=0,
                response_size=0,
                response_time=time.time() - start_time,
                content_type="",
                error="Timeout"
            )
        except Exception as e:
            return DirectoryResult(
                domain=domain,
                url=url,
                path=path,
                status_code=0,
                response_size=0,
                response_time=time.time() - start_time,
                content_type="",
                error=str(e)
            )

@tool
def directory_searcher(live_domains: List[str]) -> str:
    """
    Tool Name: directory_searcher

    Description:
    This tool performs comprehensive directory and file enumeration on a list of live subdomains.
    It uses a large wordlist containing common directories, files, and paths to discover hidden
    or interesting resources on each domain. The tool returns results grouped by domain and status code.

    Input:
    - live_domains (List[str]): A list of live domain URLs or domain names 
      (e.g., ["https://subdomain.example.com", "api.example.com"]).
      Domains without protocol will default to HTTPS.

    Output:
    - str: A JSON string in the format:
      {
        "domain_name": {
          "200": ["https://domain_name/index.php", "https://domain_name/robots.txt"],
          "403": ["https://domain_name/admin/", "https://domain_name/config/"],
          "301": ["https://domain_name/old-page"]
        }
      }
      
    Status codes included: 200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 405, 500, 503
    """
    
    async def run_directory_search():
        # Initialize the directory searcher
        searcher = DirectorySearcher(timeout=10, max_workers=15)
        
        # Run directory search
        results = await searcher.search_directories(live_domains)
        
        # Display summary
        print("\n" + "="*80)
        print("DIRECTORY SEARCH RESULTS SUMMARY")
        print("="*80)
        
        # total_found = 0
        # for domain, status_codes in results.items():
        #     domain_total = sum(len(urls) for urls in status_codes.values())
        #     total_found += domain_total
        #     print(f"\nDomain: {domain} - Found {domain_total} paths")
            
        #     for status_code, urls in status_codes.items():
        #         status_icon = "✅" if status_code == "200" else "⚠️" if status_code in ["301", "302", "403"] else "❌"
        #         print(f"  {status_icon} {status_code}: {len(urls)} paths")
                
        #         # Show first few URLs as examples
        #         for url in urls[:3]:  # Show first 3 URLs
        #             print(f"    - {url}")
        #         if len(urls) > 3:
        #             print(f"    ... and {len(urls) - 3} more")
            
        #     print("-" * 40)
        
        # print(f"\nTotal paths found across all domains: {total_found}")
        
        # Return results as JSON string
        return json.dumps(results, indent=2)
    
    # Run the async function
    try:
        loop = asyncio.get_running_loop()
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(asyncio.run, run_directory_search())
            return future.result()
    except RuntimeError:
        return asyncio.run(run_directory_search())

# Example usage for testing
# if __name__ == "__main__":
#     # Test the tool
#     test_domains = ["https://demo.testfire.net", "https://jsonplaceholder.typicode.com"]
#     result = directory_searcher(test_domains)
#     print("Result format:", result)
