import streamlit as st
from main import app  # This should be your LangGraph compiled app
from langchain.callbacks.base import BaseCallbackHandler
from langchain_core.runnables import RunnableConfig

# 🔄 1. Callback Handler to Stream LLM Output in Real Time
class StreamlitCallbackHandler(BaseCallbackHandler):
    def __init__(self, container):
        self.container = container
        self.text = ""

    def on_llm_new_token(self, token: str, **kwargs):
        self.text += token
        self.container.markdown(self.text + "▌")

# 🧠 2. Streamlit App Starts
st.set_page_config(page_title="Modular Recon", layout="wide")
st.title("🕵️ Modular Recon Workflow")

domain = st.text_input("Enter domain", value="testfire.net")

if st.button("Start Recon"):
    st.subheader("Live LLM Output")
    container = st.empty()
    handler = StreamlitCallbackHandler(container)
    config = RunnableConfig(callbacks=[handler])

    # 🌀 3. Initialize app stream with callbacks enabled
    events = app.stream(
        {
            "input": f"Perform recon on {domain}",
            "messages": [],
            "LiveDomains": [],
        },
        config=config  # ✅ pass streaming callback config
    )

    # 📤 4. Display Structured Info From Agent States
    messages = []
    for state in events:
        if "messages" in state:
            last_msg = state["messages"][-1]
            if hasattr(last_msg, "content"):
                messages.append(last_msg.content)

        if "LiveDomains" in state:
            st.success(f"Live Domains: {state['LiveDomains']}")

        if "Ports" in state:
            st.info(f"Port Scan: {state['Ports']}")

        if "TechFingerprint" in state:
            st.warning(f"Tech Fingerprint: {state['TechFingerprint']}")

        if "Directories" in state:
            st.error(f"Directories Found: {state['Directories']}")
