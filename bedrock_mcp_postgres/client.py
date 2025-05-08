# client.py
import logging
import os
from typing import Dict, List, Optional, Any, Union, Tuple

from .message import Message
from .memory import ChatMemory
from .connection import MCPServerConnection
from .config import load_mcp_config
from .bedrock import BedrockClient

logger = logging.getLogger("mcp-bedrock-client")

class GeneralMCPBedrockClient:
    """Client for MCP Servers with Bedrock Integration"""
    
    def __init__(self, region_name='us-west-2'):
        self.bedrock_client = BedrockClient(region_name=region_name)
        self.servers: Dict[str, MCPServerConnection] = {}
        self.active_server = None
        self.memory = ChatMemory()
        
        # Tool name mapping (bedrock_tool_name -> (server_name, tool_name))
        self.tool_mapping: Dict[str, Tuple[str, str]] = {}
        
        # Load MCP config
        self._load_servers()
    
    def _load_servers(self):
        """Load MCP server configurations"""
        server_configs = load_mcp_config()
        for server_name, server_url in server_configs.items():
            self.servers[server_name] = MCPServerConnection(server_name, server_url)
    
    async def connect_to_servers(self, server_names: List[str] = None):
        """Connect to specified MCP servers or all servers if none specified"""
        if not self.servers:
            raise ValueError("No servers found in configuration")
        
        if not server_names:
            server_names = list(self.servers.keys())
        
        connected_servers = []
        for name in server_names:
            if name in self.servers:
                success = await self.servers[name].connect()
                if success:
                    connected_servers.append(name)
                    # Set the first successfully connected server as active
                    if not self.active_server:
                        self.active_server = name
            else:
                logger.warning(f"Server {name} not found in configuration")
        
        if not connected_servers:
            raise RuntimeError("Failed to connect to any MCP servers")
        
        logger.info(f"Connected to servers: {', '.join(connected_servers)}")
        logger.info(f"Active server set to: {self.active_server}")
        
        return connected_servers
    
    async def cleanup(self):
        """Close all connections to MCP servers"""
        logger.info("Cleaning up resources")
        
        for server_name, server in self.servers.items():
            if server.connected:
                await server.disconnect()
    
    async def switch_active_server(self, server_name: str):
        """Switch the active server"""
        if server_name not in self.servers:
            raise ValueError(f"Server {server_name} not found")
        
        if not self.servers[server_name].connected:
            await self.servers[server_name].connect()
        
        self.active_server = server_name
        logger.info(f"Active server switched to: {server_name}")
    
    async def call_tool(self, server_name: str, tool_name: str, params: Dict[str, Any] = None) -> str:
        """Call a tool on a specific MCP server"""
        if server_name not in self.servers:
            raise ValueError(f"Server {server_name} not found")
        
        if not self.servers[server_name].connected:
            await self.servers[server_name].connect()
        
        return await self.servers[server_name].call_tool(tool_name, params)
    
    async def list_tools(self, server_name: str = None) -> List[Dict[str, Any]]:
        """List all available tools on a specific MCP server or all servers"""
        if server_name:
            if server_name not in self.servers:
                raise ValueError(f"Server {server_name} not found")
            
            if not self.servers[server_name].connected:
                await self.servers[server_name].connect()
            
            return await self.servers[server_name].list_tools()
        else:
            # List tools from all connected servers
            all_tools = []
            for name, server in self.servers.items():
                if server.connected:
                    server_tools = await server.list_tools()
                    for tool in server_tools:
                        tool['server'] = name
                    all_tools.extend(server_tools)
            return all_tools
    
    def _get_all_bedrock_tools(self) -> List[Dict]:
        """Get all tools from all connected servers formatted for Bedrock"""
        server_tools = {}
        for server_name, server in self.servers.items():
            if server.connected:
                server_tools[server_name] = server.tools
        
        bedrock_tools, tool_mapping = self.bedrock_client.format_tools_for_bedrock(server_tools)
        self.tool_mapping = tool_mapping
        return bedrock_tools
    
    async def process_query(self, query: str) -> str:
        """Process a user query through Bedrock and the MCP servers"""
        if not any(server.connected for server in self.servers.values()):
            raise RuntimeError("Not connected to any MCP servers")
        
        # Add user message to memory
        self.memory.add_user_message(query)
        
        # Get all messages from memory for context
        messages = self.memory.get_messages()
        
        # Format tools for Bedrock from all connected servers
        bedrock_tools = self._get_all_bedrock_tools()
        response = self.bedrock_client.make_request(messages, bedrock_tools)

        return await self._process_response(response, messages, bedrock_tools)
    
    async def _process_response(self, response: Dict, messages: List[Dict], bedrock_tools: List[Dict]) -> str:
        """Process the response from Bedrock, handling tool calls as needed"""
        final_text = []
        MAX_TURNS = 10
        turn_count = 0
        final_assistant_response = ""

        while True:
            if response['stopReason'] == 'tool_use':
                final_text.append("MCP Client is using tools to help with your query...")
                for item in response['output']['message']['content']:
                    if 'text' in item:
                        final_text.append(f"[Thinking: {item['text']}]")
                        messages.append(Message.assistant(item['text']).__dict__)
                    elif 'toolUse' in item:
                        tool_info = item['toolUse']
                        bedrock_tool_name = tool_info['name']
                        tool_args = tool_info['input']
                        tool_use_id = tool_info['toolUseId']
                        
                        # Look up the actual server and tool name from our mapping
                        if bedrock_tool_name in self.tool_mapping:
                            server_name, tool_name = self.tool_mapping[bedrock_tool_name]
                            
                            # Call the actual MCP tool
                            logger.debug(f"Calling MCP tool: {server_name}.{tool_name} with args: {tool_args}")
                            try:
                                result = await self.call_tool(server_name, tool_name, tool_args)
                                final_text.append(f"[Using {server_name}.{tool_name} with parameters {tool_args}]")
                                
                                # Add tool request and result to messages
                                messages.append(Message.tool_request(tool_use_id, bedrock_tool_name, tool_args).__dict__)
                                messages.append(Message.tool_result(tool_use_id, result).__dict__)
                                
                                # Add to memory
                                self.memory.add_message(Message.tool_request(tool_use_id, bedrock_tool_name, tool_args).__dict__)
                                self.memory.add_message(Message.tool_result(tool_use_id, result).__dict__)
                            except Exception as e:
                                error_msg = f"Error calling tool {server_name}.{tool_name}: {str(e)}"
                                logger.error(error_msg)
                                final_text.append(f"[Error: {error_msg}]")
                                messages.append(Message.tool_result(tool_use_id, f"Error: {error_msg}").__dict__)
                                self.memory.add_message(Message.tool_result(tool_use_id, f"Error: {error_msg}").__dict__)
                        else:
                            error_msg = f"Unknown tool: {bedrock_tool_name}"
                            logger.error(error_msg)
                            final_text.append(f"[Error: {error_msg}]")
                            messages.append(Message.tool_result(tool_use_id, f"Error: {error_msg}").__dict__)
                            self.memory.add_message(Message.tool_result(tool_use_id, f"Error: {error_msg}").__dict__)
                        
                        response = self.bedrock_client.make_request(messages, bedrock_tools)
            elif response['stopReason'] in ('max_tokens', 'stop_sequence', 'content_filtered'):
                reason_messages = {
                    'max_tokens': "[Max tokens reached, ending response.]",
                    'stop_sequence': "[Response complete.]",
                    'content_filtered': "[Content filtered, ending response.]"
                }
                final_text.append(reason_messages.get(response['stopReason'], "[Response ended.]"))
                break
            elif response['stopReason'] == 'end_turn':
                for item in response['output']['message']['content']:
                    if 'text' in item:
                        final_text.append(item['text'])
                        final_assistant_response = item['text']
                break

            turn_count += 1

            if turn_count >= MAX_TURNS:
                final_text.append("\n[Max processing steps reached, ending response.]")
                break

        # Add assistant's final response to memory
        if final_assistant_response:
            self.memory.add_assistant_message(final_assistant_response)
            
        # Update conversation summary periodically
        if len(self.memory.messages) % 5 == 0:
            await self._update_conversation_summary()
            
        return "\n\n".join(final_text)
    
    async def _update_conversation_summary(self):
        """Update the conversation summary using Bedrock"""
        if len(self.memory.messages) < 3:
            return
            
        try:
            # Create a summary request
            summary_request = [{
                "role": "user",
                "content": [{
                    "text": "Please provide a brief summary (2-3 sentences) of our conversation so far. Focus on the key questions asked and insights provided."
                }]
            }]
            
            # Add the conversation history
            summary_request.extend(self.memory.get_messages())
            
            # Make the request to Bedrock
            response = self.bedrock_client.make_request(summary_request)
            
            # Extract the summary
            if response['output']['message']['content'][0]['text']:
                summary = response['output']['message']['content'][0]['text']
                self.memory.set_summary(summary)
                logger.debug(f"Updated conversation summary: {summary}")
        except Exception as e:
            logger.error(f"Error updating conversation summary: {str(e)}")

    async def chat_loop(self):
        """Run an interactive chat loop"""
        print("\nGeneral MCP Client Started!")
        print("Type your questions or 'help' to see available commands.")
        
        while True:
            try:
                query = input("\nQuery: ").strip()
                if query.lower() in ('quit', 'exit'):
                    break
                elif query.lower() == 'servers':
                    print("\nAvailable servers:")
                    for name, server in self.servers.items():
                        status = "Connected" if server.connected else "Disconnected"
                        active = " (Active)" if name == self.active_server else ""
                        print(f"  {name} - {status}{active}")
                elif query.lower().startswith('connect '):
                    server_name = query.split(' ', 1)[1].strip()
                    if server_name in self.servers:
                        success = await self.servers[server_name].connect()
                        if success:
                            print(f"\nConnected to {server_name}")
                        else:
                            print(f"\nFailed to connect to {server_name}")
                    else:
                        print(f"\nServer {server_name} not found")
                elif query.lower().startswith('switch '):
                    server_name = query.split(' ', 1)[1].strip()
                    try:
                        await self.switch_active_server(server_name)
                        print(f"\nActive server switched to {server_name}")
                    except Exception as e:
                        print(f"\nError: {str(e)}")
                elif query.lower() == 'tools':
                    tools = await self.list_tools()
                    print("\nAvailable tools:")
                    for tool in tools:
                        server = tool.get('server', 'unknown')
                        print(f"  {server}.{tool['name']} - {tool['description']}")
                        if tool['parameters']:
                            print("    Parameters:")
                            for param_name, param_info in tool['parameters'].items():
                                param_type = param_info.get("type", "any")
                                description = param_info.get("description", "")
                                print(f"      {param_name} ({param_type}): {description}")
                elif query.lower().startswith('tools '):
                    server_name = query.split(' ', 1)[1].strip()
                    try:
                        tools = await self.list_tools(server_name)
                        print(f"\nTools for {server_name}:")
                        for tool in tools:
                            print(f"  {tool['name']} - {tool['description']}")
                            if tool['parameters']:
                                print("    Parameters:")
                                for param_name, param_info in tool['parameters'].items():
                                    param_type = param_info.get("type", "any")
                                    description = param_info.get("description", "")
                                    print(f"      {param_name} ({param_type}): {description}")
                    except Exception as e:
                        print(f"\nError: {str(e)}")
                elif query.lower() == 'help':
                    print("\nAvailable commands:")
                    print("  servers - List available servers")
                    print("  connect <server> - Connect to a specific server")
                    print("  switch <server> - Switch active server")
                    print("  tools - List tools from all connected servers")
                    print("  tools <server> - List tools from a specific server")
                    print("  help - Show this help message")
                    print("  clear - Clear conversation history")
                    print("  summary - Show conversation summary")
                    print("  quit/exit - Exit the client")
                    print("  Any other text will be processed as a query to the MCP servers")
                elif query.lower() == 'clear':
                    self.memory.clear()
                    print("\nConversation history cleared.")
                elif query.lower() == 'summary':
                    if self.memory.summary:
                        print(f"\nConversation summary: {self.memory.summary}")
                    else:
                        print("\nNo conversation summary available yet.")
                else:
                    response = await self.process_query(query)
                    print("\n" + response)
            except Exception as e:
                print(f"\nError: {str(e)}")
                import traceback
                traceback.print_exc()
