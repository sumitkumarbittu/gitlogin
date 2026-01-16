from fastapi import Form

from fastapi import FastAPI, File, UploadFile, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse, FileResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import httpx
import base64
import os
import secrets
from typing import Optional, Dict
from pydantic_settings import BaseSettings
from datetime import datetime
import logging
import json
from urllib.parse import urlencode

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# In-memory session storage (use Redis in production)
sessions = {}

class Settings(BaseSettings):
    # GitHub OAuth App credentials
    github_client_id: str
    github_client_secret: str
    
    # URLs (environment configurable)
    github_callback_url: str
    app_url: str = "http://localhost:3000"
    
    # App settings
    secret_key: str = secrets.token_hex(32)
    session_expiry: int = 3600  # 1 hour
    
    # Rate limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 60  # seconds
    
    class Config:
        env_file = ".env"

settings = Settings()

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="GitHub File Upload API with OAuth")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Static files are served inline - no separate static directory needed

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class GitHubOAuth:
    """GitHub OAuth helper class"""
    
    @staticmethod
    def get_authorization_url(state: str) -> str:
        """Generate GitHub OAuth authorization URL"""
        params = {
            "client_id": settings.github_client_id,
            "redirect_uri": settings.github_callback_url,
            "scope": "repo",
            "state": state,
            "allow_signup": "true"
        }
        return f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    
    @staticmethod
    async def exchange_code_for_token(code: str) -> str:
        """Exchange authorization code for access token"""
        url = "https://github.com/login/oauth/access_token"
        data = {
            "client_id": settings.github_client_id,
            "client_secret": settings.github_client_secret,
            "code": code,
            "redirect_uri": settings.github_callback_url
        }
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=data, headers=headers)
            if response.status_code == 200:
                token_data = response.json()
                return token_data.get("access_token")
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"Failed to get access token: {response.text}"
                )
    
    @staticmethod
    async def get_user_info(access_token: str) -> Dict:
        """Get GitHub user information"""
        url = "https://api.github.com/user"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"Failed to get user info: {response.text}"
                )

class SessionManager:
    """Simple session manager (use Redis in production)"""
    
    @staticmethod
    def create_session(user_data: Dict, access_token: str) -> str:
        """Create a new session"""
        session_id = secrets.token_urlsafe(32)
        sessions[session_id] = {
            "user": user_data,
            "access_token": access_token,
            "created_at": datetime.now().isoformat(),
            "repos": []
        }
        return session_id
    
    @staticmethod
    def get_session(session_id: str) -> Optional[Dict]:
        """Get session data"""
        if session_id in sessions:
            session = sessions[session_id]
            # Check expiry
            created_at = datetime.fromisoformat(session["created_at"])
            elapsed = (datetime.now() - created_at).seconds
            if elapsed < settings.session_expiry:
                return session
            else:
                del sessions[session_id]
        return None
    
    @staticmethod
    def update_session_repos(session_id: str, repos: list):
        """Update user's repos in session"""
        if session_id in sessions:
            sessions[session_id]["repos"] = repos
    
    @staticmethod
    def delete_session(session_id: str):
        """Delete session"""
        if session_id in sessions:
            del sessions[session_id]

@app.get("/", response_class=HTMLResponse)
@limiter.limit(f"{settings.rate_limit_requests}/{settings.rate_limit_window}seconds")
async def home(request: Request):
    """Serve the main HTML file"""
    logger.info(f"Access: Home page requested from {request.client.host}")
    try:
        return FileResponse("index.html")
    except Exception as e:
        logger.error(f"Error serving home page: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")



@app.get("/auth/login")
@limiter.limit("10/minute")
async def login(request: Request):
    """Start GitHub OAuth flow"""
    logger.info(f"Access: OAuth login requested from {request.client.host}")
    try:
        state = secrets.token_urlsafe(16)
        auth_url = GitHubOAuth.get_authorization_url(state)
        
        # Store state in session or cookie
        response = RedirectResponse(auth_url)
        response.set_cookie(key="oauth_state", value=state, httponly=True, max_age=300)
        logger.info(f"OAuth flow initiated with state: {state}")
        return response
    except Exception as e:
        logger.error(f"Error initiating OAuth flow: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to initiate OAuth flow")

@app.get("/auth/callback")
async def auth_callback(request: Request, code: str, state: Optional[str] = None):
    """OAuth callback endpoint"""
    logger.info(f"Access: OAuth callback received with state: {state}")
    
    # Verify state
    stored_state = request.cookies.get("oauth_state")
    if not stored_state or stored_state != state:
        logger.warning(f"Security: Invalid state parameter. Expected: {stored_state}, Received: {state}")
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    try:
        # Exchange code for token
        logger.info("Exchanging authorization code for access token")
        access_token = await GitHubOAuth.exchange_code_for_token(code)
        
        # Get user info
        logger.info("Fetching user information from GitHub")
        user_info = await GitHubOAuth.get_user_info(access_token)
        logger.info(f"User authenticated: {user_info.get('login', 'unknown')}")
        
        # Create session
        session_id = SessionManager.create_session(user_info, access_token)
        logger.info(f"Session created: {session_id[:8]}...")
        
        # Redirect to home (serves index.html)
        response = RedirectResponse(url="/")
        response.set_cookie(key="session_id", value=session_id, httponly=True, max_age=settings.session_expiry)
        response.delete_cookie(key="oauth_state")
        return response
        
    except Exception as e:
        logger.error(f"OAuth error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/auth/logout")
async def logout(request: Request):
    """Logout user"""
    session_id = request.cookies.get("session_id")
    if session_id:
        SessionManager.delete_session(session_id)
    
    response = RedirectResponse(url="/")
    response.delete_cookie(key="session_id")
    return response

@app.get("/auth/status")
async def auth_status(request: Request):
    """Check authentication status"""
    session_id = request.cookies.get("session_id")
    if not session_id:
        return {"authenticated": False}
    
    session = SessionManager.get_session(session_id)
    if session:
        return {
            "authenticated": True,
            "user": session["user"],
            "has_repo": bool(session.get("repos"))
        }
    return {"authenticated": False}

async def get_authenticated_user(request: Request) -> Dict:
    """Get authenticated user from session"""
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    session = SessionManager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Session expired")
    
    return session

@app.get("/api/user")
async def get_user(request: Request):
    """Get current user info"""
    session = await get_authenticated_user(request)
    return {
        "authenticated": True,
        "user": session["user"],
        "repos": session.get("repos", [])
    }

@app.get("/api/repos")
async def get_user_repos(request: Request):
    """Get user's repositories"""
    session = await get_authenticated_user(request)
    access_token = session["access_token"]
    
    url = "https://api.github.com/user/repos"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers, params={"per_page": 100})
        if response.status_code == 200:
            repos = response.json()
            
            # Filter and format repos
            formatted_repos = [
                {
                    "name": repo["name"],
                    "full_name": repo["full_name"],
                    "private": repo["private"],
                    "html_url": repo["html_url"],
                    "description": repo.get("description", ""),
                    "default_branch": repo["default_branch"]
                }
                for repo in repos
            ]
            
            # Store in session
            SessionManager.update_session_repos(request.cookies.get("session_id"), formatted_repos)
            
            return formatted_repos
        else:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Failed to get repos: {response.text}"
            )

async def upload_to_github(
    filename: str, 
    content: bytes, 
    repo_full_name: str,
    access_token: str,
    path: Optional[str] = None,
    branch: str = "main"
):
    """Upload a file to GitHub repository"""
    # Encode file content
    encoded_content = base64.b64encode(content).decode('utf-8')
    
    # Construct file path in repo
    if path:
        file_path = f"{path}/{filename}"
    else:
        file_path = f"uploads/{filename}"
    
    # GitHub API URL
    url = f"https://api.github.com/repos/{repo_full_name}/contents/{file_path}"
    
    # Prepare headers
    headers = {
        "Authorization": f"Bearer {access_token}",
        "User-Agent": "FastAPI-GitHub-Uploader",
        "Accept": "application/vnd.github.v3+json"
    }
    
    async with httpx.AsyncClient() as client:
        # Check if file exists to get SHA for update
        try:
            check_response = await client.get(
                url, 
                headers=headers, 
                params={"ref": branch}
            )
            sha = check_response.json().get("sha") if check_response.status_code == 200 else None
        except Exception as e:
            logger.error(f"Error checking file existence: {e}")
            sha = None
        
        # Prepare commit data
        commit_data = {
            "message": f"Upload: {filename} via GitHub Uploader - {datetime.now().isoformat()}",
            "content": encoded_content,
            "branch": branch
        }
        
        # Add SHA if file exists (for update)
        if sha:
            commit_data["sha"] = sha
        
        # Upload/Update file
        response = await client.put(url, headers=headers, json=commit_data)
        
        if response.status_code in [200, 201]:
            return response.json()
        else:
            logger.error(f"GitHub API error: {response.status_code} - {response.text}")
            raise HTTPException(
                status_code=response.status_code,
                detail=f"GitHub API error: {response.text}"
            )

@app.post("/api/upload")
@limiter.limit("20/minute")
async def upload_files(
    request: Request,
    files: list[UploadFile] = File(...),
    repo: str = Form(...),
    path: Optional[str] = Form(None),
    branch: Optional[str] = Form("main")
):
    """Upload multiple files to GitHub repository"""
    client_ip = request.client.host
    logger.info(f"Access: File upload requested from {client_ip} to repo: {repo}")
    
    try:
        session = await get_authenticated_user(request)
        access_token = session["access_token"]
        
        uploaded = []
        
        for file in files:
            logger.info(f"Processing file: {file.filename} ({len(await file.read())} bytes)")
            await file.seek(0)  # Reset file pointer
            content = await file.read()
            filename = file.filename
            
            result = await upload_to_github(
                filename,
                content,
                repo,
                access_token,
                path,
                branch
            )
            
            uploaded.append({
                "filename": filename,
                "url": result["content"]["html_url"]
            })
            logger.info(f"Successfully uploaded: {filename}")
        
        logger.info(f"Upload completed: {len(uploaded)} files to {repo}")
        return {
            "success": True,
            "uploaded_files": uploaded
        }
        
    except Exception as e:
        logger.error(f"Upload error from {client_ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.get("/api/repo/{repo_full_name}/contents")
async def list_repo_contents(
    request: Request,
    repo_full_name: str,
    path: Optional[str] = None
):
    """List contents of a repository"""
    session = await get_authenticated_user(request)
    access_token = session["access_token"]
    
    target_path = path or ""
    url = f"https://api.github.com/repos/{repo_full_name}/contents/{target_path}"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.get(url, headers=headers)
        
        if response.status_code == 200:
            items = response.json()
            files = []
            directories = []
            
            for item in items:
                if isinstance(item, dict):
                    item_data = {
                        "name": item["name"],
                        "type": item["type"],
                        "size": item.get("size", 0),
                        "sha": item["sha"],
                        "url": item["html_url"],
                        "download_url": item.get("download_url"),
                        "path": item["path"]
                    }
                    
                    if item["type"] == "file":
                        files.append(item_data)
                    else:
                        directories.append(item_data)
            
            return {
                "path": target_path,
                "files": files,
                "directories": directories
            }
        elif response.status_code == 404:
            return {"path": target_path, "files": [], "directories": []}
        else:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Failed to list contents: {response.text}"
            )

@app.post("/api/repo/create")
async def create_repository(
    request: Request,
    name: str = Form(...),
    description: Optional[str] = Form(None),
    private: bool = Form(False)
):
    """Create a new repository"""
    session = await get_authenticated_user(request)
    access_token = session["access_token"]
    
    url = "https://api.github.com/user/repos"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    data = {
        "name": name,
        "description": description,
        "private": private,
        "auto_init": True  # Initialize with README
    }
    
    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers, json=data)
        
        if response.status_code == 201:
            repo_data = response.json()
            return {
                "success": True,
                "message": "Repository created successfully",
                "repo": {
                    "name": repo_data["name"],
                    "full_name": repo_data["full_name"],
                    "html_url": repo_data["html_url"],
                    "clone_url": repo_data["clone_url"]
                }
            }
        else:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Failed to create repository: {response.text}"
            )

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"success": False, "error": exc.detail}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=3000,
        reload=True
    )