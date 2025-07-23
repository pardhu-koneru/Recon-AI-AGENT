import sys
import os
import ast
# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(os.path.dirname(__file__), 'agents'))

import re
from typing import List

from schema import AgentState
from typing import TypedDict, Annotated, List, Dict, Any
from langgraph.graph import StateGraph,END
from langgraph.graph.message import add_messages
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.runnables import RunnableConfig
# from agents.subdomain_agent import run_subdomain_enumeration,get_subdomain_list
from agents.subdomain_agent import agent_executor as subdomain_agent
from agents.portscanner_agent import agent_executor as portscanner_agent
from agents.technology_fingerprinting_agent import agent_executor as technology_fingerprinter
from agents.dirsearch_agent import agent_executor as dirsearch_agent

from agents.LiveDomain import chain


# from agents.portscanner_agent import agent_executor as portscanner_agent
    
# Define workflow

import re
from typing import List

def run_subdomain_agent(state: AgentState, config: RunnableConfig = None):
    """Wrapper function to run the subdomain agent"""
    try:
        result = subdomain_agent.invoke({
            "input": state["input"]},
            config=config
        )

        return {
            "messages": [AIMessage(content=str(result["output"]))],
        }

    except Exception as e:
        return {
            "messages": [AIMessage(content=f"Error: {str(e)}")],
            
        }



def get_live_subdomains(state: AgentState ,config: RunnableConfig = None):
    """Wrapper function to get the live subdomains from the subdomain agent output"""
    subdomain_agent_output = state["messages"][-1].content
    
    try:
        result = chain.invoke({
            "content":subdomain_agent_output
        },config=config)
        lines = result.content.strip().splitlines()
        for line in lines:
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                subdomain_list = ast.literal_eval(line)
                break
        else:
            subdomain_list = []
            
        return {
            "LiveDomains": subdomain_list
        }
    except Exception as e:
        return {
            "LiveDomains": [], 
        }

def run_port_scanner(state: AgentState, config: RunnableConfig = None):
    """Wrapper function to run the port scanner agent on live subdomains"""
    try:
        result = portscanner_agent.invoke({
            "input": state["LiveDomains"],
        }
        ,config=config)

        return {
            
            "Ports": result["output"]
        }

    except Exception as e:
        return {
            "messages": [AIMessage(content=f"Error: {str(e)}")],
            
        }
    
def technology_fingerprinting(state: AgentState, config: RunnableConfig = None):
    """Wrapper function to run the technology_fingerprinting_agent on live subdomains"""
    try:
        result = technology_fingerprinter.invoke({
            "test_domains": state["LiveDomains"]
        }
        ,config=config)

        return {
            "TechFingerprint": result["output"]
        }

    except Exception as e:
        return {
            "messages": [AIMessage(content=f"Error: {str(e)}")],
            
        }


def directorySearch(state: AgentState, config: RunnableConfig = None):
    """Wrapper function to run the dirsearch_agent  on live subdomains"""
    try:
        result = dirsearch_agent.invoke({
            "live_domains": state["LiveDomains"]
        }
        ,config=config) 

        return {
            "Directories": result["output"]
        }

    except Exception as e:
        return {
            "messages": [AIMessage(content=f"Error: {str(e)}")],
            
        }
    
       
workflow = StateGraph(AgentState)


# Add nodes
workflow.add_node("subdomain_scan", run_subdomain_agent)
workflow.add_node("LiveDomains",get_live_subdomains)
workflow.add_node("portscan", run_port_scanner)
workflow.add_node("fingerprinting", technology_fingerprinting)
workflow.add_node("dirsearch", directorySearch)

workflow.add_edge("subdomain_scan","LiveDomains")
workflow.add_edge("LiveDomains","portscan")
workflow.add_edge("portscan", "fingerprinting")
workflow.add_edge("fingerprinting", "dirsearch")
workflow.add_edge("dirsearch", END)

# Set entry point
workflow.set_entry_point("subdomain_scan")


# Compile the workflow
app = workflow.compile()

if __name__ == "__main__":
    # Example invocation with error handling
    try:
        result = app.invoke({
            "input": "Perform recon on www.testfire.net",
            "messages": [],
            "LiveDomains":[],
            
        })
        
        print("\n=== Scan Results ===")
        print(result)
        
        if "error" in result:
            print(f"\nError occurred")
            
    except Exception as e:
        print(f"Fatal error in workflow execution: {str(e)}")