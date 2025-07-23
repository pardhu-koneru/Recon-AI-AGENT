import os
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_groq import ChatGroq
from tools.dirsearch_tool import directory_searcher

from schema import AgentState
state = AgentState()

from dotenv import load_dotenv
load_dotenv()

os.environ["GROQ_API_KEY"] = os.getenv("GROQ_API_KEY")

tools = [directory_searcher]

prompt = ChatPromptTemplate.from_messages([
    ("system", 
     """You are a cybersecurity reconnaissance agent specialized in directory enumeration and web path discovery.

You will be provided with a List[str] of live domains/subdomains. Your job is to iterate over each domain and discover hidden directories, files, and endpoints that may be valuable for security assessment.

You will use a directory search tool that performs the following actions:

- Enumerates directories and files using a comprehensive wordlist (800+ entries)
- Tests for common admin panels, API endpoints, configuration files, and backup files
- Checks for development/staging environments and debug files  
- Discovers CMS-specific paths (WordPress, Drupal, Joomla)
- Identifies version control directories (.git, .svn)
- Finds security-sensitive files (.env, config files, database dumps)
- Returns results grouped by domain and HTTP status code

The tool tests paths including:
- Admin areas: /admin, /administrator, /dashboard, /cpanel
- API endpoints: /api, /rest, /graphql, /v1, /v2
- Config files: config.php, .env, web.config, .htaccess
- Backup files: backup.zip, dump.sql, database.sql
- Development: /test, /debug, /staging, /dev
- Common files: robots.txt, sitemap.xml, phpinfo.php

For each domain, return results in this format:
{{
  "example.com": {{
    "200": ["https://example.com/found-page.php", "https://example.com/admin/"],
    "403": ["https://example.com/private/", "https://example.com/config/"],
    "301": ["https://example.com/old-admin"]
  }}
}}

Status codes returned:
- 200/20x: Successfully accessible resources
- 301/302: Redirects that may reveal other paths
- 403: Forbidden areas (often indicate interesting directories)
- 401: Authentication required (potential admin areas)
- 500: Server errors (may indicate misconfigurations)

Process all domains from the provided list and focus on paths that are most valuable for security assessment and bug bounty hunting.
Highlight any discovered admin panels, API endpoints, configuration files, or backup files.

After running the directory search tool, analyze the results and provide:
1. Summary of total paths discovered across all domains
2. Critical findings (admin panels, config files, backups)
3. Interesting findings (API endpoints, debug files, version control)
4. Security recommendations based on discovered paths

"""),
    ("human", "List of live domains/subdomains to enumerate: {live_domains}\n\nRun the directory search tool on all provided domains and analyze the discovered paths for security assessment."),
    MessagesPlaceholder("agent_scratchpad")
])

llm = ChatGroq(
    model="llama3-8b-8192",
    temperature=0.1,  # Low temperature for consistent, factual responses
    max_tokens=4000   # Increased for detailed responses
)

# Create the agent
agent = create_tool_calling_agent(llm, tools, prompt)

# Create the agent executor with enhanced configuration
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True,
    handle_parsing_errors=True,
    early_stopping_method="force",
    return_intermediate_steps=True
)

# Helper function to run directory enumeration
async def run_directory_enumeration(domains: list, max_retries: int = 2):
    """
    Run directory enumeration on a list of domains with retry logic
    
    Args:
        domains: List of domain URLs or domain names
        max_retries: Number of retries if the agent fails
    
    Returns:
        Agent response with discovered directories
    """
    for attempt in range(max_retries + 1):
        try:
            response = await agent_executor.ainvoke({
                "live_domains": domains
            })
            
            # Extract the final output
            if isinstance(response.get("output"), str):
                return response["output"]
            else:
                return response
                
        except Exception as e:
            print(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt == max_retries:
                return {"error": f"Directory enumeration failed after {max_retries + 1} attempts: {str(e)}"}
            
            # Wait before retry
            import asyncio
            await asyncio.sleep(2)

# Synchronous wrapper for the agent
def enumerate_directories(domains: list):
    """
    Synchronous wrapper to run directory enumeration
    
    Args:
        domains: List of domain URLs or domain names
        
    Returns:
        Directory enumeration results
    """
    try:
        response = agent_executor.invoke({
            "live_domains": domains
        })
        
        return response.get("output", response)
        
    except Exception as e:
        return {"error": f"Directory enumeration failed: {str(e)}"}

# Analysis helper functions
def analyze_directory_results(results_json: str):
    """
    Analyze directory enumeration results and highlight interesting findings
    
    Args:
        results_json: JSON string from directory_searcher tool
        
    Returns:
        Analysis summary with security insights
    """
    try:
        import json
        results = json.loads(results_json) if isinstance(results_json, str) else results_json
        
        analysis = {
            "total_domains": len(results),
            "total_paths_found": 0,
            "critical_findings": [],
            "interesting_findings": [],
            "domain_summary": {}
        }
        
        critical_patterns = [
            "admin", "administrator", "wp-admin", "phpmyadmin", "cpanel",
            "config", ".env", "backup", "database", "dump.sql",
            ".git", "debug", "test", "api", "swagger"
        ]
        
        for domain, status_codes in results.items():
            domain_paths = sum(len(urls) for urls in status_codes.values())
            analysis["total_paths_found"] += domain_paths
            
            analysis["domain_summary"][domain] = {
                "total_paths": domain_paths,
                "status_breakdown": {code: len(urls) for code, urls in status_codes.items()}
            }
            
            # Analyze for critical findings
            for status_code, urls in status_codes.items():
                for url in urls:
                    url_lower = url.lower()
                    for pattern in critical_patterns:
                        if pattern in url_lower:
                            finding = {
                                "domain": domain,
                                "url": url,
                                "status": status_code,
                                "type": pattern,
                                "risk_level": "HIGH" if pattern in ["admin", "config", ".env", "backup"] else "MEDIUM"
                            }
                            
                            if finding["risk_level"] == "HIGH":
                                analysis["critical_findings"].append(finding)
                            else:
                                analysis["interesting_findings"].append(finding)
                            break
        
        return analysis
        
    except Exception as e:
        return {"error": f"Analysis failed: {str(e)}"}

# Example usage
# if __name__ == "__main__":
#     # Test domains
#     test_domains = [
#         "https://example.com",
#         "https://subdomain.example.com", 
#         "api.example.com"
#     ]
    
#     print("Starting directory enumeration...")
#     results = enumerate_directories(test_domains)
    
#     if isinstance(results, dict) and "error" not in results:
#         print("\n" + "="*80)
#         print("DIRECTORY ENUMERATION COMPLETED")
#         print("="*80)
        
#         # Analyze results if it's JSON
#         try:
#             analysis = analyze_directory_results(results)
            
#             print(f"\nSummary:")
#             print(f"- Total domains scanned: {analysis.get('total_domains', 0)}")
#             print(f"- Total paths discovered: {analysis.get('total_paths_found', 0)}")
#             print(f"- Critical findings: {len(analysis.get('critical_findings', []))}")
#             print(f"- Interesting findings: {len(analysis.get('interesting_findings', []))}")
            
#             # Show critical findings
#             if analysis.get('critical_findings'):
#                 print("\n🚨 CRITICAL FINDINGS:")
#                 for finding in analysis['critical_findings'][:5]:  # Show first 5
#                     print(f"  - {finding['url']} ({finding['status']}) - {finding['type']}")
#         except:
#             pass
        
#         print(f"\nFull results: {str(results)[:500]}...")
#     else:
#         print(f"❌ Enumeration failed: {results}")
