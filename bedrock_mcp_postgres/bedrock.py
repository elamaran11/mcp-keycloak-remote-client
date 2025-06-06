import boto3
import logging
import time
import random
import hashlib
import json
import botocore.exceptions
from typing import Dict, List, Tuple, Any

logger = logging.getLogger("mcp-bedrock-client")

class BedrockClient:
    """Client for interacting with Amazon Bedrock"""
    
    DEFAULT_MODEL_ID = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    #DEFAULT_MODEL_ID = "us.amazon.nova-pro-v1:0"
    DEFAULT_REGION = "us-west-2"
    
    def __init__(self, model_id=None, region_name=None):
        """
        Initialize the Bedrock client
        
        Args:
            model_id (str, optional): The model ID to use. Defaults to Claude 3 Sonnet.
            region_name (str, optional): AWS region to use. Defaults to us-west-2.
        """
        self.MODEL_ID = model_id if model_id else self.DEFAULT_MODEL_ID
        region = region_name if region_name else self.DEFAULT_REGION
        
        logger.info(f"Initializing Bedrock client with model {self.MODEL_ID} in region {region}")
        self.bedrock = boto3.client(service_name='bedrock-runtime', region_name=region)
        self.response_cache = {}
        
    def is_nova_model(self):
        """Check if the current model is a Nova model"""
        return "nova" in self.MODEL_ID.lower()
    
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
        """Make a request to Amazon Bedrock with exponential backoff and caching"""
        # Generate cache key for identical requests
        cache_key = hashlib.md5(json.dumps({"messages": messages, "tools": tools, "model": self.MODEL_ID}).encode()).hexdigest()
        
        # Check cache for identical requests
        if cache_key in self.response_cache:
            logger.info("Using cached response")
            return self.response_cache[cache_key]
        
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
        
        # Implement exponential backoff
        max_retries = 8
        retry_count = 0
        
        # Set base delay based on model type
        if self.is_nova_model():
            base_delay = 2  # Longer base delay for Nova models
        else:
            base_delay = 1
        
        while True:
            try:
                response = self.bedrock.converse(**request_params)
                # Cache the successful response
                self.response_cache[cache_key] = response
                return response
            
            except botocore.exceptions.ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                
                # Handle throttling errors specifically
                if error_code == 'ThrottlingException' and retry_count < max_retries:
                    retry_count += 1
                    # Calculate exponential backoff with jitter
                    delay = (2 ** retry_count) * base_delay + random.uniform(0, 1)
                    logger.warning(f"Throttling detected. Retrying in {delay:.2f} seconds (attempt {retry_count}/{max_retries})")
                    time.sleep(delay)
                else:
                    # For other errors or if we've exhausted retries
                    logger.error(f"Bedrock API error: {error_code} - {e}")
                    raise
    
    def batch_tool_calls(self, messages, tool_calls, max_batch_size=3):
        """Process multiple tool calls in batches to avoid throttling"""
        results = []
        for i in range(0, len(tool_calls), max_batch_size):
            batch = tool_calls[i:i+max_batch_size]
            # Process batch
            for tool_call in batch:
                # Add tool call processing logic here
                pass
            
            # Add delay between batches to avoid throttling
            if i + max_batch_size < len(tool_calls):
                delay = 1.0 if not self.is_nova_model() else 2.0
                time.sleep(delay)
                
        return results