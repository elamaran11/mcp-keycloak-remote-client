# mcp-client-bedrock
This MCP client runs stand alone in any environment with Amazon Bedrock Models supported for Tool Use

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

# You should have IAM access to bedrock models from the enviroment you are executing

# Create virtual environment- Make sure you have stable python version (ex 3.12 above)

python3.12 -m venv venv

source venv/bin/activate

python3 -m bedrock_mcp_postgres --region us-west-2
