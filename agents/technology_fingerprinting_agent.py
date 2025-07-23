import os
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_groq import ChatGroq
from tools.technology_fingerprint_tool import technology_fingerprinter

from schema import AgentState
state = AgentState()

from dotenv import load_dotenv
load_dotenv()

os.environ["GROQ_API_KEY"] = os.getenv("GROQ_API_KEY")

tools = [technology_fingerprinter]

prompt = ChatPromptTemplate.from_messages([
    ("system", 
     """You are a cybersecurity reconnaissance agent specialized in technology fingerprinting.
Your job is to analyze a list of live domains and identify the technologies used by each one.
You will use a fingerprinting tool that performs the following actions:

- Detects web technologies such as CMS (e.g., WordPress), JavaScript frameworks (e.g., React, Vue), CSS frameworks (e.g., Bootstrap), and server types (e.g., Apache, Nginx).
- Collects HTTP headers from each domain.
- Returns HTTP status codes to validate reachability.
- Outputs the results in structured JSON format.

For each live domain, return:
- domain: base domain name
- url: full scanned URL
- status_code: HTTP response status code
- technologies: a dictionary categorized by tech types and their detected values
- headers: key HTTP response headers

Ensure the results are clean, structured, and useful for a bug bounty hunter.

"""),
    ("human", "List of live domains to analyze:\n\n{test_domains}\n\nRun the fingerprinting tool and return the structured JSON results."),
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
    # max_iterations=4,  # Allow multiple iterations for complex queries
    return_intermediate_steps=True
)