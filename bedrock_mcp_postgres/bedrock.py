# bedrock.py
import boto3
import logging
from typing import Dict, List, Tuple, Any

logger = logging.getLogger("mcp-bedrock-client")

class BedrockClient:
    """Client for interacting with Amazon Bedrock"""
    
    DEFAULT_MODEL_ID = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    #DEFAULT_MODEL_ID = "anthropic.claude-3-7-sonnet-20240620-v1:0"
    DEFAULT_REGION = "us-west-2"
    
    def __init__(self, model_id=None, region_name=None):
        """
        Initialize the Bedrock client
        
        Args:
            model_id (str, optional): The model ID to use. Defaults to Claude 3 Haiku.
            region_name (str, optional): AWS region to use. Defaults to us-west-2.
        """
        self.MODEL_ID = model_id if model_id else self.DEFAULT_MODEL_ID
        region = region_name if region_name else self.DEFAULT_REGION
        
        logger.info(f"Initializing Bedrock client with model {self.MODEL_ID} in region {region}")
        self.bedrock = boto3.client(service_name='bedrock-runtime', region_name=region)
    
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
        # Determine appropriate max tokens based on model
        max_tokens = 4096
        if "nova" in self.MODEL_ID.lower():
            max_tokens = 10000
        elif "mistral" in self.MODEL_ID.lower() or "jamba" in self.MODEL_ID.lower() or "pixtral" in self.MODEL_ID.lower():
            max_tokens = 8192
        
        request_params = {
            "modelId": self.MODEL_ID,
            "messages": messages,
            "inferenceConfig": {"maxTokens": max_tokens, "temperature": 0}
        }
        
        if tools:
            request_params["toolConfig"] = {"tools": tools}
        
        return self.bedrock.converse(**request_params)