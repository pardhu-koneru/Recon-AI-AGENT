from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_groq import ChatGroq
from tools.port_scanner_tool import run_port_scanner
import os
from dotenv import load_dotenv

load_dotenv()

# Import the new tools
tools = [run_port_scanner]

# Set up API key
os.environ["GROQ_API_KEY"] = os.getenv("GROQ_API_KEY")

# Enhanced prompt for better agent behavior
prompt = ChatPromptTemplate.from_messages([
    (
        "system", 
        """You are a Port Scanning Output Agent in a modular recon system.
          You are a Port Scanning Agent in a modular recon system.
          Your job is to scan all live subdomains provided as a list of strings.
          Your job is to:
          
          1. Extract and list the open ports for each domain from the input text.
          2. Include the service name (like HTTP, SSH) next to each open port.
          3. Return the result strictly as a **valid Python-style JSON dictionary** 
             where:
             - Keys are domain names (strings)
             - Values are dictionaries mapping port numbers (integers) to service names (strings)
          
          4. Skip domains that failed to resolve or had no open ports.
          5. Do not include explanations, markdown, or extra commentary—return **only the JSON object**.
          
          Make sure the output format matches this structure:
          
          {{
            "domain1.com": {{
              80: "HTTP",
              443: "HTTPS"
            }},
            "sub.domain2.com": {{
              22: "SSH",
              3306: "MySQL"
            }}
          }}
          """
              ),
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

