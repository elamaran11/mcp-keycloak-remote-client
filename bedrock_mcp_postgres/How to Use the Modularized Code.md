## How to Use the Modularized Code

After organizing the code into these files, you can use the client as follows:

# Example usage

from bedrock_mcp_postgres import GeneralMCPBedrockClient
import asyncio

async def run_client():
    client = GeneralMCPBedrockClient()
    try:
        await client.connect_to_servers()
        response = await client.process_query("What tools are available?")
        print(response)
    finally:
        await client.cleanup()

if __name__ == "__main__":
    asyncio.run(run_client())
    
## Or use the CLI directly:

python3 -m bedrock_mcp_postgres --region us-west-2

This modular structure separates concerns, making the code more maintainable and easier to extend. Each file has a specific responsibility, and the dependencies between components are clear.
