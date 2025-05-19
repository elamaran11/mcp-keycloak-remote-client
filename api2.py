import asyncio
import logging
import os
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import quote
import secrets

import httpx
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Form, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from bedrock_mcp_postgres.client import GeneralMCPBedrockClient
from bedrock_mcp_postgres.bedrock import BedrockClient
from bedrock_mcp_postgres.config import load_mcp_config
from jose import jwt, jwk
from jose.exceptions import JWTError

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("mcp-bedrock-client-api")

# Keycloak Configuration
KEYCLOAK_URL = "https://auth.elamaras.people.aws.dev"
REALM_NAME = "fastapi-realm"
KEYCLOAK_CLIENT_ID = "fastapi-client"
KEYCLOAK_CLIENT_SECRET = "XXXX"  # Replace with your actual client secret
REDIRECT_URL = "http://aiagent.elamaras.people.aws.dev/callback"
JWKS_URL = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/certs"

app = FastAPI(title="MCP Bedrock Client API")

# Templates
templates = Jinja2Templates(directory="templates")

# Session and clients store
sessions: Dict[str, dict] = {}
clients = {}

# Models
class TokenData(BaseModel):
    username: str
    roles: List[str]

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

# Session management functions
def get_session(request: Request) -> dict:
    session_id = request.cookies.get("session_id")
    if session_id and session_id in sessions:
        return sessions[session_id]
    return {}

def set_session(response: Response, session_data: dict) -> str:
    session_id = secrets.token_urlsafe(32)
    sessions[session_id] = session_data
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        max_age=3600,
        samesite="lax"
    )
    return session_id

# Token validation function
async def validate_token(token: str) -> TokenData:
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(JWKS_URL)
            response.raise_for_status()
            jwks = response.json()

        headers = jwt.get_unverified_headers(token)
        kid = headers.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Token missing 'kid' header")

        key_data = next((key for key in jwks["keys"] if key["kid"] == kid), None)
        if not key_data:
            raise HTTPException(status_code=401, detail="Matching key not found in JWKS")

        public_key = jwk.construct(key_data).public_key()

        payload = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            audience=KEYCLOAK_CLIENT_ID,
            options={"verify_aud": False}
        )

        username = payload.get("preferred_username")
        roles = payload.get("realm_access", {}).get("roles", [])
        if not username or not roles:
            raise HTTPException(status_code=401, detail="Token missing required claims")

        return TokenData(username=username, roles=roles)

    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")

# Helper function for role checking
async def check_role(request: Request, required_role: str) -> bool:
    session_data = get_session(request)
    if not session_data or "access_token" not in session_data:
        return False
    try:
        token_data = await validate_token(session_data["access_token"])
        return required_role in token_data.roles
    except HTTPException:
        return False

# Authentication middleware
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    protected_paths = ["/protected", "/admin"]

    if any(request.url.path.startswith(path) for path in protected_paths):
        session_data = get_session(request)
        if not session_data or "access_token" not in session_data:
            return RedirectResponse(url="/login")

        try:
            await validate_token(session_data["access_token"])
        except HTTPException:
            return RedirectResponse(url="/login")

    response = await call_next(request)
    return response
# Routes
@app.get("/")
async def root():
    return RedirectResponse(url="/protected")

@app.get("/login")
async def login(request: Request):
    logger.info("Login route accessed")
    auth_url = (
        f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/auth"
        f"?client_id={KEYCLOAK_CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={quote(REDIRECT_URL)}"
        f"&scope=openid profile email"
    )
    logger.info(f"Redirecting to Keycloak: {auth_url}")
    return RedirectResponse(url=auth_url)

@app.get("/callback")
async def callback(code: str, request: Request):
    logger.info("Callback route accessed")
    token_url = f"{KEYCLOAK_URL}/realms/{REALM_NAME}/protocol/openid-connect/token"

    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            token_url,
            data={
                "grant_type": "authorization_code",
                "client_id": KEYCLOAK_CLIENT_ID,
                "client_secret": KEYCLOAK_CLIENT_SECRET,
                "code": code,
                "redirect_uri": REDIRECT_URL
            }
        )

    if token_response.status_code != 200:
        raise HTTPException(status_code=400, detail="Token exchange failed")

    tokens = token_response.json()
    response = RedirectResponse(url="/protected")

    session_data = {
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"]
    }
    set_session(response, session_data)

    return response

@app.get("/logout")
async def logout(request: Request):
    logger.info("Logout route accessed")
    session_id = request.cookies.get("session_id")
    if session_id in sessions:
        del sessions[session_id]

    response = RedirectResponse(url="/login")
    response.delete_cookie("session_id")
    return response

@app.get("/protected", response_class=HTMLResponse)
async def protected_home(request: Request):
    session_data = get_session(request)
    if not session_data or "access_token" not in session_data:
        return RedirectResponse(url="/login")

    try:
        user_data = await validate_token(session_data["access_token"])
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "user": user_data}
        )
    except HTTPException:
        return RedirectResponse(url="/login")

@app.get("/web/connect", response_class=HTMLResponse)
async def web_connect_form(request: Request):
    config = load_mcp_config()
    servers = list(config.keys())
    models, regions = load_supported_models()

    if not models:
        models = [
            {"id": "anthropic.claude-3-5-sonnet-20240620-v2:0", "name": "Claude 3.5 Sonnet (us-west-2)", "region": "us-west-2"},
            {"id": "anthropic.claude-3-7-sonnet-20240620-v1:0", "name": "Claude 3.7 Sonnet (us-west-2)", "region": "us-west-2"},
            {"id": "anthropic.claude-3-haiku-20240307-v1:0", "name": "Claude 3 Haiku (us-west-2)", "region": "us-west-2"}
        ]

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
    try:
        client = GeneralMCPBedrockClient(region_name=region)
        client.bedrock_client = BedrockClient(model_id=model_id, region_name=region)

        connected_servers = await client.connect_to_servers(servers)

        if not connected_servers:
            return templates.TemplateResponse(
                "error.html",
                {"request": request, "error": "Failed to connect to any servers"}
            )

        session_id = secrets.token_urlsafe()

        clients[session_id] = {
            "client": client,
            "model_id": model_id,
            "region": region,
            "connected_servers": connected_servers,
            "chat_history": []
        }

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
    try:
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

        logger.info(f"Retrieved connected servers for session {session_id}: {connected_servers}")

        response = await client.process_query(query)

        chat_history.append({"query": query, "response": response})
        client_info["chat_history"] = chat_history

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
                "chat_history": chat_history[:-1]
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
        client = GeneralMCPBedrockClient(region_name=request.region)
        client.bedrock_client = BedrockClient(model_id=request.model_id, region_name=request.region)

        connected_servers = await client.connect_to_servers(request.servers)

        if not connected_servers:
            raise HTTPException(status_code=500, detail="Failed to connect to any servers")

        session_id = secrets.token_urlsafe()

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
        client_info = clients.get(request.session_id)
        if not client_info:
            raise HTTPException(status_code=404, detail="Session not found")

        client = client_info["client"]
        chat_history = client_info.get("chat_history", [])

        response = await client.process_query(request.query)

        chat_history.append({"query": request.query, "response": response})
        client_info["chat_history"] = chat_history

        return QueryResponse(response=response)
    except Exception as e:
        logger.error(f"Query error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Query error: {str(e)}")

@app.get("/servers")
def list_servers():
    try:
        config = load_mcp_config()
        return {"servers": list(config.keys())}
    except Exception as e:
        logger.error(f"Error listing servers: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error listing servers: {str(e)}")

@app.get("/models")
def list_models():
    try:
        models, regions = load_supported_models()
        return {"models": models, "regions": regions}
    except Exception as e:
        logger.error(f"Error listing models: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error listing models: {str(e)}")

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.delete("/session/{session_id}")
async def cleanup_session(session_id: str, background_tasks: BackgroundTasks):
    if session_id in clients:
        client_info = clients[session_id]
        client = client_info["client"]
        background_tasks.add_task(client.cleanup)
        del clients[session_id]
        return {"message": "Session cleaned up"}
    raise HTTPException(status_code=404, detail="Session not found")

# Helper function to load models
def load_supported_models():
    models = {}
    regions = set()

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

    formatted_models = []
    for model_name, region_data in models.items():
        for region, model_id in region_data.items():
            formatted_models.append({
                "id": model_id,
                "name": f"{model_name} ({region})",
                "region": region
            })

    return formatted_models, sorted(list(regions))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=4001)
