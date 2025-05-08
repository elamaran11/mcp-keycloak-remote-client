# cli.py
import argparse
import anyio
import logging
from .client import GeneralMCPBedrockClient

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-bedrock-client")

async def main():
    parser = argparse.ArgumentParser(description='General MCP Client with Bedrock')
    parser.add_argument('--servers', type=str, help='Comma-separated list of server names to connect to')
    parser.add_argument('--region', type=str, default='us-west-2', help='AWS region for Bedrock')
    
    args = parser.parse_args()
    
    client = GeneralMCPBedrockClient(region_name=args.region)
    
    try:
        server_names = args.servers.split(',') if args.servers else None
        await client.connect_to_servers(server_names)
        await client.chat_loop()
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        await client.cleanup()

def cli():
    """Command-line interface for the client"""
    anyio.run(main, backend="asyncio")

if __name__ == "__main__":
    cli()