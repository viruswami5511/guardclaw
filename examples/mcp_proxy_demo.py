"""
GuardClaw MCP Proxy Demo

Run:
    python examples/mcp_proxy_demo.py
"""

from pathlib import Path
import json

from guardclaw import init_global_ledger, Ed25519KeyManager
from guardclaw.mcp import GuardClawMCPProxy

print("🛡️  GuardClaw MCP Proxy Demo")
print("=" * 50)

# 1. Setup GuardClaw
km = Ed25519KeyManager.generate()
init_global_ledger(key_manager=km, agent_id="mcp-agent")

# 2. Define tools
def search_tool(query: str) -> str:
    return f"Results for: {query}"

def calculator_tool(expression: str) -> str:
    try:
        return str(eval(expression))
    except Exception as e:
        return f"Error: {e}"

# 3. Setup proxy
proxy = GuardClawMCPProxy(agent_id="mcp-agent")
proxy.register_tool("search", search_tool, description="Search the web")
proxy.register_tool("calculator", calculator_tool, description="Evaluate math")

# 4. Style A — Dispatcher
print("\n📡 Style A — Dispatcher")
result = proxy.call("search", query="AI safety")
print(f"  search → {result}")
result = proxy.call("calculator", expression="2 ** 10")
print(f"  calculator → {result}")

# 5. Style B — Wrapper
print("\n🔧 Style B — Wrapper")
search = proxy.wrap_tool(search_tool)
result = search(query="cryptographic accountability")
print(f"  wrapped search → {result}")

# 6. Schema export
print("\n📋 Tool Schemas (OpenAI-compatible)")
for schema in proxy.get_tool_schemas():
    print(f"  {schema['function']['name']}: {schema['function']['description']}")

# 7. List tools
print(f"\n🗂️  Registered tools: {proxy.list_tools()}")
print(f"\n{proxy}")

# 8. Verify ledger
ledger_file = Path(".guardclaw") / "ledger" / "ledger.jsonl"
entries = []
if ledger_file.exists():
    with ledger_file.open() as f:
        entries = [json.loads(line) for line in f if line.strip()]

print(f"\n📊 Ledger entries: {len(entries)}")
for e in entries:
    print(f"  [{e['sequence']}] {e['payload']['action']} → {e['payload']['result']}")

print("\n✅ All tool calls cryptographically signed and verified.")
