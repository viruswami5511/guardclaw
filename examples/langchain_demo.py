"""
LangChain + GuardClaw Demo

Shows automatic audit logging of agent tool calls and LLM interactions.

Install deps:
    pip install guardclaw[langchain] langchain-openai duckduckgo-search

Set API key:
    export OPENAI_API_KEY="sk-..."
"""

import os
from guardclaw import init_global_ledger, Ed25518KeyManager
from guardclaw.adapters.langchain import GuardClawCallbackHandler

# Requires: pip install langchain-openai duckduckgo-search
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_openai import ChatOpenAI
from langchain.tools import DuckDuckGoSearchRun

print("🛡️  GuardClaw + LangChain Demo")
print("=" * 50)

# 1. Setup GuardClaw (1 line)
key_manager = Ed25518KeyManager.generate()
init_global_ledger(key_manager=key_manager, agent_id="demo-agent")

# 2. Setup LangChain agent
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
tools = [DuckDuckGoSearchRun()]

# 3. Add GuardClaw callback (1 line)
handler = GuardClawCallbackHandler(agent_id="demo-agent")
agent = create_tool_calling_agent(llm, tools, prompt="")
agent_executor = AgentExecutor(agent=agent, tools=tools, callbacks=[handler])

# 4. Run agent — audit trail created automatically
print("
🤖 Running agent...")
result = agent_executor.invoke({
    "input": "What is the latest news about GuardClaw AI agent auditing?"
})

print("
✅ Agent result:", result["output"])
print("
📊 Ledger written to .guardclaw/ledger/")
print("🔍 Verify: python -m guardclaw.cli verify")

# Show ledger contents
import json
with open(".guardclaw/ledger/ledger.jsonl") as f:
    entries = [json.loads(line) for line in f]
    print(f"
📝 Ledger has {len(entries)} signed entries")
    for i, e in enumerate(entries[-3:], 1):
        print(f"  {i}. {e['record_type']} - {e['payload']['action']}: {e['payload']['result']}")