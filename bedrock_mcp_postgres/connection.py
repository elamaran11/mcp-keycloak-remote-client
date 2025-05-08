# connection.py
import logging
from typing import Dict, List, Optional, Any
from mcp import ClientSession
from mcp.client.sse import sse_client
from .memory import ChatMemory

logger = logging.getLogger("mcp-bedrock-client")

class MCPServerConnection:
    """Represents a connection to a specific MCP server"""
    
    def __init__(self, server_name: str, server_url: str):
        self.server_name = server_name
        self.server_url = server_url
        self.session: Optional[ClientSession] = None
        self._streams_context = None
        self._session_context = None
        self.tools = []
        self.memory = ChatMemory()
        self.connected = False
        
    async def connect(self):
        """Connect to the MCP server using SSE"""
        logger.info(f"Connecting to MCP server {self.server_name}: {self.server_url}")
        
        # Extract base URL if full SSE URL was provided
        if self.server_url.endswith('/sse'):
            self.server_url = self.server_url.rsplit('/sse', 1)[0]
        
        # Create SSE client
        sse_url = f"{self.server_url}/sse"
        logger.info(f"Using SSE endpoint: {sse_url}")
        
        try:
            self._streams_context = sse_client(url=sse_url)
            streams = await self._streams_context.__aenter__()
            
            # Initialize session
            self._session_context = ClientSession(*streams)
            self.session = await self._session_context.__aenter__()
            
            # Initialize the session
            logger.info(f"Initializing session for {self.server_name}...")
            await self.session.initialize()
            logger.info(f"Session for {self.server_name} initialized successfully")
            
            # List available tools
            response = await self.session.list_tools()
            self.tools = response.tools
            tool_names = [tool.name for tool in self.tools]
            logger.info(f"Available tools for {self.server_name}: {', '.join(tool_names)}")
            self.connected = True
            return True
        except Exception as e:
            logger.error(f"Failed to connect to {self.server_name}: {str(e)}")
            await self.disconnect()
            return False
    
    async def disconnect(self):
        """Close the connection to the MCP server"""
        logger.info(f"Disconnecting from {self.server_name}")
        
        if self._session_context:
            await self._session_context.__aexit__(None, None, None)
            self._session_context = None
            
        if self._streams_context:
            await self._streams_context.__aexit__(None, None, None)
            self._streams_context = None
            
        self.session = None
        self.connected = False
    
    async def call_tool(self, tool_name: str, params: Dict[str, Any] = None) -> str:
        """Call a tool on the MCP server"""
        if not self.session:
            raise RuntimeError(f"Not connected to {self.server_name} MCP server")
        
        if not params:
            params = {}
        
        logger.debug(f"Calling tool on {self.server_name}: {tool_name}")
        result = await self.session.call_tool(tool_name, params)
        
        # Extract text from the result
        if hasattr(result, 'content') and result.content:
            if hasattr(result.content[0], 'text'):
                return result.content[0].text
            return str(result.content[0])
        return str(result)
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """List all available tools on the MCP server"""
        if not self.session:
            raise RuntimeError(f"Not connected to {self.server_name} MCP server")
        
        response = await self.session.list_tools()
        tools = response.tools
        
        tools_info = []
        for tool in tools:
            tools_info.append({
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.inputSchema.get("properties", {}) if tool.inputSchema else {}
            })
        
        return tools_info