#api.py
import asyncio
import logging
import os
from typing import Dict, List, Optional, Any, Tuple
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from bedrock_mcp_postgres.client import GeneralMCPBedrockClient
from bedrock_mcp_postgres.bedrock import BedrockClient
from bedrock_mcp_postgres.config import load_mcp_config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-bedrock-client-api")

app = FastAPI(title="MCP Bedrock Client API")

# Set up templates
templates = Jinja2Templates(directory="templates")

# Store clients by session ID
clients = {}

# Function to load models from model_tooluse.txt
def load_supported_models():
    """Load supported models from model_tooluse.txt file"""
    models = {}
    regions = set()
    
    # Path to model_tooluse.txt file
    model_file_path = os.path.join(os.path.dirname(__file__), "model_tooluse.txt")
    
    try:
        with open(model_file_path, 'r') as file:
            model_data = file.read()
            
            for line in model_data.strip().split('\n'):
                parts = line.split('|')
                if len(parts) >= 5:
                    model_name = parts[0].strip()
                    model_id = parts[2].strip()
                    region = parts[3].strip()
                    
                    if model_name not in models:
                        models[model_name] = {}
                    
                    models[model_name][region] = model_id
                    regions.add(region)
    except Exception as e:
        logger.error(f"Error loading model data: {str(e)}")
        return [], []
    
    # Format models for the UI
    formatted_models = []
    for model_name, region_data in models.items():
        for region, model_id in region_data.items():
            formatted_models.append({
                "id": model_id,
                "name": f"{model_name} ({region})",
                "region": region
            })
    
    return formatted_models, sorted(list(regions))

# Pydantic models for request/response
class ConnectRequest(BaseModel):
    region: str
    model_id: str
    servers: List[str]

class QueryRequest(BaseModel):
    session_id: str
    query: str

class ConnectResponse(BaseModel):
    session_id: str
    connected_servers: List[str]

class QueryResponse(BaseModel):
    response: str

# Helper function to run async code
def run_async(func, *args):
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(func(*args))

# Web UI routes
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Home page with links to web UI"""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/web/connect", response_class=HTMLResponse)
async def web_connect_form(request: Request):
    """Web form for connecting to servers"""
    # Get available servers
    config = load_mcp_config()
    servers = list(config.keys())
    
    # Get available models and regions
    models, regions = load_supported_models()
    
    # If no models found, provide some defaults
    if not models:
        models = [
            {"id": "anthropic.claude-3-5-sonnet-20240620-v2:0", "name": "Claude 3.5 Sonnet (us-west-2)", "region": "us-west-2"},
            {"id": "anthropic.claude-3-7-sonnet-20240620-v1:0", "name": "Claude 3.7 Sonnet (us-west-2)", "region": "us-west-2"},
            {"id": "anthropic.claude-3-haiku-20240307-v1:0", "name": "Claude 3 Haiku (us-west-2)", "region": "us-west-2"}
        ]
    
    # If no regions found, provide some defaults
    if not regions:
        regions = ["us-east-1", "us-west-2", "eu-west-1"]
    
    return templates.TemplateResponse(
        "connect.html", 
        {
            "request": request, 
            "servers": servers,
            "models": models,
            "regions": regions
        }
    )

@app.post("/web/connect", response_class=HTMLResponse)
async def web_connect(
    request: Request,
    region: str = Form(...),
    model_id: str = Form(...),
    servers: List[str] = Form(...)
):
    """Process the connect form submission"""
    try:
        # Create client
        client = GeneralMCPBedrockClient(region_name=region)
        client.bedrock_client = BedrockClient(model_id=model_id, region_name=region)
        
        # Connect to servers
        connected_servers = await client.connect_to_servers(servers)
        
        if not connected_servers:
            return templates.TemplateResponse(
                "error.html", 
                {"request": request, "error": "Failed to connect to any servers"}
            )
        
        # Generate session ID
        import uuid
        session_id = str(uuid.uuid4())
        
        # Store client and session info
        clients[session_id] = {
            "client": client,
            "model_id": model_id,
            "region": region,
            "connected_servers": connected_servers,
            "chat_history": []  # Initialize empty chat history
        }
        
        # Debug - log what we're storing
        logger.info(f"Connected servers for session {session_id}: {connected_servers}")
        
        return templates.TemplateResponse(
            "chat.html", 
            {
                "request": request, 
                "session_id": session_id,
                "connected_servers": connected_servers,
                "model_id": model_id,
                "region": region
            }
        )
    except Exception as e:
        logger.error(f"Connection error: {str(e)}", exc_info=True)
        return templates.TemplateResponse(
            "error.html", 
            {"request": request, "error": f"Connection error: {str(e)}"}
        )

@app.post("/web/query", response_class=HTMLResponse)
async def web_query(
    request: Request,
    session_id: str = Form(...),
    query: str = Form(...)
):
    """Process a query from the web UI"""
    try:
        # Get client info
        client_info = clients.get(session_id)
        if not client_info:
            return templates.TemplateResponse(
                "error.html", 
                {"request": request, "error": "Session not found or expired"}
            )
        
        client = client_info["client"]
        model_id = client_info["model_id"]
        region = client_info["region"]
        connected_servers = client_info["connected_servers"]
        chat_history = client_info.get("chat_history", [])
        
        # Debug - log what we're retrieving
        logger.info(f"Retrieved connected servers for session {session_id}: {connected_servers}")
        
        # Process query
        response = await client.process_query(query)
        
        # Add this exchange to chat history
        chat_history.append({"query": query, "response": response})
        client_info["chat_history"] = chat_history  # Update the stored history
        
        return templates.TemplateResponse(
            "response.html", 
            {
                "request": request, 
                "session_id": session_id,
                "query": query,
                "response": response,
                "connected_servers": connected_servers,
                "model_id": model_id,
                "region": region,
                "chat_history": chat_history[:-1]  # All but current exchange
            }
        )
    except Exception as e:
        logger.error(f"Query error: {str(e)}", exc_info=True)
        return templates.TemplateResponse(
            "error.html", 
            {"request": request, "error": f"Query error: {str(e)}"}
        )

# API routes
@app.post("/connect", response_model=ConnectResponse)
async def connect(request: ConnectRequest):
    try:
        # Create client
        client = GeneralMCPBedrockClient(region_name=request.region)
        client.bedrock_client = BedrockClient(model_id=request.model_id, region_name=request.region)
        
        # Connect to servers
        connected_servers = await client.connect_to_servers(request.servers)
        
        if not connected_servers:
            raise HTTPException(status_code=500, detail="Failed to connect to any servers")
        
        # Generate session ID
        import uuid
        session_id = str(uuid.uuid4())
        
        # Store client and session info
        clients[session_id] = {
            "client": client,
            "model_id": request.model_id,
            "region": request.region,
            "connected_servers": connected_servers,
            "chat_history": []
        }
        
        return ConnectResponse(session_id=session_id, connected_servers=connected_servers)
    except Exception as e:
        logger.error(f"Connection error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Connection error: {str(e)}")

@app.post("/query", response_model=QueryResponse)
async def query(request: QueryRequest):
    try:
        # Get client info
        client_info = clients.get(request.session_id)
        if not client_info:
            raise HTTPException(status_code=404, detail="Session not found")
        
        client = client_info["client"]
        chat_history = client_info.get("chat_history", [])
        
        # Process query
        response = await client.process_query(request.query)
        
        # Add to chat history
        chat_history.append({"query": request.query, "response": response})
        client_info["chat_history"] = chat_history
        
        return QueryResponse(response=response)
    except Exception as e:
        logger.error(f"Query error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Query error: {str(e)}")

# List available servers from config
@app.get("/servers")
def list_servers():
    try:
        config = load_mcp_config()
        return {"servers": list(config.keys())}
    except Exception as e:
        logger.error(f"Error listing servers: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error listing servers: {str(e)}")

# List available models
@app.get("/models")
def list_models():
    try:
        models, regions = load_supported_models()
        return {"models": models, "regions": regions}
    except Exception as e:
        logger.error(f"Error listing models: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error listing models: {str(e)}")

# Health check endpoint
@app.get("/health")
def health_check():
    return {"status": "healthy"}

# Cleanup session
@app.delete("/session/{session_id}")
async def cleanup_session(session_id: str, background_tasks: BackgroundTasks):
    if session_id in clients:
        client_info = clients[session_id]
        client = client_info["client"]
        background_tasks.add_task(client.cleanup)
        del clients[session_id]
        return {"message": "Session cleaned up"}
    raise HTTPException(status_code=404, detail="Session not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=4001)