# utils.py
import logging
from typing import Dict, Any

logger = logging.getLogger("mcp-bedrock-client")

def format_tool_response(response: Dict[str, Any]) -> str:
    """Format a tool response for display"""
    try:
        if isinstance(response, dict):
            if 'error' in response:
                return f"Error: {response['error']}"
            elif 'result' in response:
                return str(response['result'])
        return str(response)
    except Exception as e:
        logger.error(f"Error formatting tool response: {str(e)}")
        return str(response)