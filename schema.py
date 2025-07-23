from typing import TypedDict, Annotated, List, Dict, Any
from langgraph.graph.message import add_messages

class AgentState(TypedDict):
    """State definition for our workflow"""
    input: str
    messages: Annotated[List[Dict[str, Any]], add_messages]
    LiveDomains:List[str]
    Ports:Dict[str, Dict[int, str]]
    TechFingerprint:Any
    Directories:Dict[str, List[str]]
    