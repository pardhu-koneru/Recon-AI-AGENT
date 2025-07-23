import os
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_groq import ChatGroq

os.environ["GROQ_API_KEY"] = os.getenv("GROQ_API_KEY")

prompt = ChatPromptTemplate([
    ("system", """You are an expert cybersecurity agent specialized in subdomain enumeration. Your task is to extract live subdomains from reports.You will be given a report generated from a subdomain enumeration scan. 

    Your task is to extract only the live subdomains from the report and return them **strictly** as a Python list of strings, like this:
    ["sub1.example.com", "sub2.example.com", "sub3.example.com"]

    Do not include IP addresses, ports, status codes, or explanations—just the list of verified live subdomains in the specified format.

    ---

    Report:
    {content}

    ---
    Return:""")
])

llm = ChatGroq(
    model="llama3-8b-8192",
    temperature=0,  # Low temperature for consistent, factual responses
    max_tokens=4000   # Increased for detailed responses
)

chain = prompt | llm

