# bedrock.py
import boto3
import logging
from typing import Dict, List, Tuple, Any

logger = logging.getLogger("mcp-bedrock-client")

class BedrockClient:
    """Client for interacting with Amazon Bedrock"""
    
    MODEL_ID = "anthropic.claude-3-5-sonnet-20240620-v1:0"
    
    def __init__(self, region_name='us-west-2'):
        self.bedrock = boto3.client(service_name='bedrock-runtime', region_name=region_name)
    
    def format_tools_for_bedrock(self, server_tools: Dict[str, List]) -> Tuple[List[Dict], Dict[str, Tuple[str, str]]]:
        """Format tools from all servers for Bedrock API"""
        all_tools = []
        tool_mapping = {}  # bedrock_tool_name -> (server_name, tool_name)
        
        for server_name, tools in server_tools.items():
            for tool in tools:
                if tool.inputSchema and 'properties' in tool.inputSchema:
                    schema = {
                        "type": "object",
                        "properties": tool.inputSchema["properties"]
                    }
                    
                    # Add required fields if they exist
                    if "required" in tool.inputSchema:
                        schema["required"] = tool.inputSchema["required"]
                    
                    # Create a Bedrock-compatible tool name (no dots)
                    bedrock_tool_name = f"{server_name}_{tool.name}"
                    
                    # Store the mapping
                    tool_mapping[bedrock_tool_name] = (server_name, tool.name)
                    
                    all_tools.append({
                        "toolSpec": {
                            "name": bedrock_tool_name,
                            "description": f"[{server_name}] {tool.description}",
                            "inputSchema": {
                                "json": schema
                            }
                        }
                    })
        
        return all_tools, tool_mapping
    
    def make_request(self, messages: List[Dict], tools: List[Dict] = None) -> Dict:
        """Make a request to Amazon Bedrock"""
        request_params = {
            "modelId": self.MODEL_ID,
            "messages": messages,
            "inferenceConfig": {"maxTokens": 8000, "temperature": 0}
        }
        
        if tools:
            request_params["toolConfig"] = {"tools": tools}
        
        return self.bedrock.converse(**request_params)