# 🔎 Modular Reconnaissance Workflow with LangGraph Agents

This project is a modular, agent-based reconnaissance automation framework built using **LangGraph**, **LangChain**, and **Streamlit**. It performs full-stack recon on any given domain through a sequence of intelligent agents, each responsible for a specific task in the recon pipeline.

---

## 🧠 Features

- 🔍 **Subdomain Enumeration Agent**  
  Discovers subdomains using multiple OSINT and DNS-based sources.

- 🌐 **Live Subdomain Filter**  
  Uses LLM-based logic to parse and validate live subdomains from the results.

- 🚪 **Port Scanning Agent**  
  Scans live domains for open ports using `nmap`.

- 🧬 **Technology Fingerprinting Agent**  
  Analyzes HTTP responses to detect web technologies and frameworks.

- 📁 **Directory Enumeration Agent**  
  Crawls accessible directories on discovered subdomains.

---

## 🕹️ Tech Stack

- 🧱 **LangGraph**: Orchestrates the recon flow using stateful agents and workflows.  
- 💬 **LangChain Agents**: Handles individual tasks like port scanning, fingerprinting, etc.  
- 🧪 **Streamlit UI**: Offers an interactive frontend to trigger recon and display live results.  
- 🔁 **Streaming Support**: Enables live feedback from LLM agents as they run.

---

## 🚀 How It Works

1. **User Input**  
   The user enters a domain name in the Streamlit-based UI.

2. **LangGraph Execution Pipeline**  
   A sequence of agents is triggered in the following order:

    Subdomain Enumeration
    ↓
    Live Domain Filtering
    ↓
    Port Scanning
    ↓
    Technology Fingerprinting
    ↓
    Directory Enumeration
3. **Real-Time Streaming**  
All agent results are streamed live to the UI, allowing the user to observe the recon process dynamically as it happens.

---

## 📦 Installation

```bash
# Clone the repository
git clone git@github.com:pardhu-koneru/Recon-AI-AGENT.git

# Navigate into the project directory
cd Recon-AI-AGENT

# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run app.py
