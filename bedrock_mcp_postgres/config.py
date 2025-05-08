# config.py
import os
import json
import logging
from typing import Dict, Optional

logger = logging.getLogger("mcp-bedrock-client")

def load_mcp_config() -> Dict:
    """Load MCP server configurations from the config file"""
    config_path = os.path.expanduser("~/.aws/amazonq/mcp.json")
    servers = {}
    
    # Verify config file exists
    if os.path.exists(config_path):
        # Load config to get server URLs
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            if "mcpServers" in config:
                for server_name, server_config in config["mcpServers"].items():
                    args = server_config.get("args", [])
                    if len(args) > 1:
                        server_url = args[1]
                        logger.info(f"Found server {server_name} with URL: {server_url}")
                        servers[server_name] = server_url
                    else:
                        logger.warning(f"Could not find URL for server {server_name} in MCP config")
            else:
                logger.warning("No MCP servers found in config")
        except Exception as e:
            logger.error(f"Error loading MCP config: {str(e)}")
    else:
        logger.warning(f"MCP config file not found at {config_path}")
    
    return servers