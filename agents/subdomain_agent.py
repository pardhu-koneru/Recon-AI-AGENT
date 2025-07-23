"""
agents/subdomain_agent.py
Updated Subdomain Agent using advanced enumeration tools
"""
import os
import sys
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_groq import ChatGroq
from tools.subdomain_enum_tool import subdomain_scan, subdomain_list

from dotenv import load_dotenv
from schema import AgentState
state = AgentState()
load_dotenv()

# Import the new tools
tools = [subdomain_scan, subdomain_list]

# Set up API key
os.environ["GROQ_API_KEY"] = os.getenv("GROQ_API_KEY")

# Enhanced prompt for better agent behavior
prompt = ChatPromptTemplate.from_messages([
    ("system", """You are an expert cybersecurity reconnaissance agent specialized in subdomain enumeration.

Your capabilities include:
- Comprehensive subdomain discovery using multiple methods (DNS brute force, Certificate Transparency, API sources)
- Live subdomain verification and analysis
- Technology fingerprinting and SSL validation
- Detailed reporting with actionable intelligence

When performing subdomain enumeration:
1. Always use the subdomain_scan tool for comprehensive analysis
2. Provide clear, structured summaries of findings
3. Highlight critical security-relevant discoveries
4. Explain the significance of findings in context of reconnaissance
5. Suggest next steps for further investigation


Be precise, thorough, and security-focused in your analysis."""),
    ("user", "{input}"),
    MessagesPlaceholder("agent_scratchpad")
])

# Initialize the LLM
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
    max_iterations=3,  # Allow multiple iterations for complex queries
    early_stopping_method="generate",
    return_intermediate_steps=True
)

# Function to run the agent with error handling
def run_subdomain_enumeration(target_domain: str) -> dict:
    """
    Run subdomain enumeration for a target domain
    
    Args:
        target_domain: The domain to enumerate subdomains for
    
    Returns:
        Dictionary containing the enumeration results
    """
    try:
        result = agent_executor.invoke({
            "input": f"Perform comprehensive subdomain enumeration for {target_domain}. "
                    f"Provide a detailed analysis of findings including live subdomains, "
                    f"technologies detected, and security implications."
        })
       
        return {
            "success": True,
            "output": result["output"],
            "intermediate_steps": result.get("intermediate_steps", [])
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "output": f"Failed to enumerate subdomains for {target_domain}: {str(e)}"
        }

# Alternative function for simple subdomain listing
def get_subdomain_list(target_domain: str) -> dict:
    """
    Get a simple list of live subdomains for a target domain
    
    Args:
        target_domain: The domain to enumerate subdomains for
    
    Returns:
        Dictionary containing the subdomain list
    """
    try:
        result = agent_executor.invoke({
            "input": f"Get a list of live subdomains for {target_domain}"
        })
        # print("Live domains result:- ",result["output"])
        # live_domains= result["output"].splitlines() if result["output"] else []
        return {
            "success": True,
            "output": result["output"],
            
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "output": f"Failed to get subdomain list for {target_domain}: {str(e)}"
        }

# Export the agent executor for use in main.py
__all__ = ['agent_executor', 'run_subdomain_enumeration', 'get_subdomain_list']