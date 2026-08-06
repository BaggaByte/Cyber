import asyncio
import os
from contextlib import AsyncExitStack
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from dotenv import load_dotenv

# Load environment variables (like ANTHROPIC_API_KEY)
load_dotenv()

class SagaMCPClient:
    """
    The Universal MCP Bridge for Saga-AI.
    Connects Claude 3.5 Sonnet to local security tools (Nuclei, MSF, Semgrep).
    """
    def __init__(self):
        self.session: ClientSession | None = None
        self.exit_stack = AsyncExitStack()

    async def connect_to_server(self, server_script_path: str):
        """Spins up a local tool server and establishes the MCP transport tunnel."""
        print(f"[*] Initializing MCP transport for: {server_script_path}")
        
        # Verify the script actually exists before trying to run it
        if not os.path.exists(server_script_path):
            raise FileNotFoundError(f"MCP Server script not found at: {server_script_path}")
        
        # Define the execution parameters (running the server via Python)
        server_params = StdioServerParameters(
            command="python",
            args=[server_script_path],
            env={**os.environ} # Pass environment variables down to the tools
        )
        
        # Open the standard I/O transport stream securely
        stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
        self.stdio, self.write = stdio_transport
        
        # Establish the formal JSON-RPC session over the I/O tunnel
        self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))
        await self.session.initialize()
        
        # Dynamically discover what tools this specific server provides
        tools_response = await self.session.list_tools()
        tools = [tool.name for tool in tools_response.tools]
        print(f"[+] MCP Server Connected. Tools unlocked: {tools}")
        
        # Return the structured tool definitions so LangGraph can pass them to Claude
        return tools_response.tools

    async def execute_tool(self, tool_name: str, arguments: dict):
        """Executes a tool natively through the MCP protocol."""
        if not self.session:
            raise RuntimeError("MCP Session is not initialized. Cannot execute tool.")
        
        print(f"[*] Claude requested execution of tool: {tool_name}")
        
        # Call the tool and return the result back to the LLM
        result = await self.session.call_tool(tool_name, arguments)
        return result
        
    async def cleanup(self):
        """Gracefully shuts down the transport tunnel to prevent memory/process leaks."""
        await self.exit_stack.aclose()
        print("[*] MCP Transport Tunnel closed successfully.")

# Expose a singleton instance if needed for simpler imports
mcp_bridge = SagaMCPClient()