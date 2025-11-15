# server.py - Production-Ready with Security Hardening
import os
import time
import uuid
import base64
import asyncio
import logging
from typing import Dict, Optional
from collections import OrderedDict
from contextlib import asynccontextmanager

from dotenv import load_dotenv
load_dotenv()


from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
import jwt  # PyJWT
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# ----------------------------
# Configuration & Logging
# ----------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ----------------------------
# Environment Variables Validation
# ----------------------------
def validate_environment():
    """Validate required environment variables at startup"""
    required_vars = {
        "SECRET_KEY": "JWT signing key (min 32 chars)",
        "CORS_ALLOW_ORIGINS": "Comma-separated list of allowed origins",
    }
    
    missing = []
    for var, description in required_vars.items():
        if not os.getenv(var):
            missing.append(f"{var} ({description})")
    
    if missing:
        error_msg = "Missing required environment variables:\n" + "\n".join(f"  - {m}" for m in missing)
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    # Validate SECRET_KEY length
    secret_key = os.getenv("SECRET_KEY", "")
    if len(secret_key) < 32:
        raise ValueError("SECRET_KEY must be at least 32 characters long")
    
    logger.info("✓ Environment variables validated successfully")

# Load configuration
try:
    validate_environment()
except ValueError as e:
    logger.critical(f"Configuration error: {e}")
    raise

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
TOKEN_AUDIENCE = os.getenv("TOKEN_AUD")
TOKEN_ISSUER = os.getenv("TOKEN_ISSUER")
CORS_ORIGINS = os.getenv("CORS_ALLOW_ORIGINS").split(",")
MAX_TASK_AGE = int(os.getenv("MAX_TASK_AGE", "300"))  # 5 minutes default
MAX_SCREENSHOT_SIZE = int(os.getenv("MAX_SCREENSHOT_SIZE", "10485760"))  # 10MB default

logger.info(f"✓ CORS origins configured: {CORS_ORIGINS}")
logger.info(f"✓ Task TTL: {MAX_TASK_AGE} seconds")
logger.info(f"✓ Max screenshot size: {MAX_SCREENSHOT_SIZE / 1024 / 1024:.1f}MB")

# ----------------------------
# Rate Limiting
# ----------------------------
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100/hour"],
    storage_uri="memory://",
)

# ----------------------------
# Lifespan Management
# ----------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    logger.info("🚀 Application starting up...")
    logger.info(f"✓ Using algorithm: {ALGORITHM}")
    
    # Start background task cleanup
    cleanup_task = asyncio.create_task(periodic_cleanup())
    
    yield
    
    # Cleanup on shutdown
    logger.info("🛑 Application shutting down...")
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    logger.info("✓ Cleanup completed")

# ----------------------------
# FastAPI App
# ----------------------------
app = FastAPI(
    title="Game Automation Backend",
    description="Receives screenshots, queues processing, returns actions. Secured by JWT.",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Rate limiter state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ----------------------------
# CORS Configuration
# ----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=3600,  # Cache preflight requests for 1 hour
)

# ----------------------------
# Security Headers Middleware
# ----------------------------
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

# ----------------------------
# Request Timeout Middleware
# ----------------------------
@app.middleware("http")
async def timeout_middleware(request: Request, call_next):
    try:
        return await asyncio.wait_for(call_next(request), timeout=30.0)
    except asyncio.TimeoutError:
        logger.warning(f"Request timeout: {request.method} {request.url.path}")
        return JSONResponse(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            content={"detail": "Request timeout"}
        )

# ----------------------------
# Logging Middleware (Safe)
# ----------------------------
SENSITIVE_HEADERS = {"authorization", "x-api-key", "cookie"}

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    # Log request (without sensitive data)
    logger.info(f"→ {request.method} {request.url.path} from {request.client.host if request.client else 'unknown'}")
    
    response = await call_next(request)
    
    # Log response time
    duration = time.time() - start_time
    logger.info(f"← {request.method} {request.url.path} - {response.status_code} ({duration:.3f}s)")
    
    return response

# ----------------------------
# Security (JWT Bearer)
# ----------------------------
security = HTTPBearer(auto_error=True)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    """
    Verify JWT token with comprehensive validation
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            audience=TOKEN_AUDIENCE if TOKEN_AUDIENCE else None,
            issuer=TOKEN_ISSUER if TOKEN_ISSUER else None,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": bool(TOKEN_AUDIENCE),
                "verify_iss": bool(TOKEN_ISSUER),
                "require_exp": True,
            },
        )
        logger.debug(f"Token verified for subject: {payload.get('sub', 'unknown')}")
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidAudienceError:
        logger.warning("Invalid token audience")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token audience",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidIssuerError:
        logger.warning("Invalid token issuer")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token issuer",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

# ----------------------------
# In-Memory Task Store with TTL
# ----------------------------
TASK_RESULTS: OrderedDict[str, Dict] = OrderedDict()

def cleanup_old_tasks() -> int:
    """Remove tasks older than MAX_TASK_AGE seconds"""
    current_time = time.time()
    expired = [
        task_id for task_id, result in TASK_RESULTS.items()
        if current_time - result.get("timestamp", 0) > MAX_TASK_AGE
    ]
    
    for task_id in expired:
        TASK_RESULTS.pop(task_id, None)
    
    if expired:
        logger.debug(f"Cleaned up {len(expired)} expired tasks")
    
    return len(expired)

async def periodic_cleanup():
    """Background task to periodically clean up old tasks"""
    while True:
        try:
            await asyncio.sleep(60)  # Run every minute
            count = cleanup_old_tasks()
            if count > 0:
                logger.info(f"Periodic cleanup: removed {count} expired tasks")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in periodic cleanup: {e}")

# ----------------------------
# Schemas with Validation
# ----------------------------
class ScreenPayload(BaseModel):
    screenshot: str  # base64-encoded PNG/JPEG
    
    @field_validator('screenshot')
    @classmethod
    def validate_screenshot(cls, v: str) -> str:
        # Check size
        if len(v) > MAX_SCREENSHOT_SIZE:
            raise ValueError(f"Screenshot too large (max {MAX_SCREENSHOT_SIZE / 1024 / 1024:.1f}MB)")
        
        # Verify it's valid base64
        try:
            decoded = base64.b64decode(v, validate=True)
            
            # Basic validation: check for common image headers
            if not (decoded.startswith(b'\x89PNG') or  # PNG
                    decoded.startswith(b'\xff\xd8\xff') or  # JPEG
                    decoded.startswith(b'GIF')):  # GIF
                raise ValueError("Invalid image format. Only PNG, JPEG, or GIF allowed")
                
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding or corrupted image: {str(e)}")
        
        return v

class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: Optional[str] = None

class ResultResponse(BaseModel):
    status: str
    action: Optional[str] = None
    reason: Optional[str] = None
    timestamp: Optional[float] = None

class HealthResponse(BaseModel):
    status: str
    timestamp: float
    tasks_in_memory: int
    uptime_seconds: float

# ----------------------------
# Background Processing
# ----------------------------
async def process_screenshot(task_id: str, screenshot_b64: str) -> None:
    """
    Process screenshot with proper error handling
    """
    try:
        logger.info(f"Processing task {task_id}")
        
        # Decode image
        try:
            image_data = base64.b64decode(screenshot_b64, validate=True)
            logger.debug(f"Decoded image size: {len(image_data)} bytes")
        except Exception as e:
            logger.error(f"Failed to decode image for task {task_id}: {e}")
            TASK_RESULTS[task_id] = {
                "status": "error",
                "action": None,
                "reason": "Invalid image data",
                "timestamp": time.time(),
            }
            return
        
        # Simulate processing (replace with your AI model)
        await asyncio.sleep(1.0)
        
        # TODO: Replace with actual AI/vision processing
        # Example: action = analyze_with_model(image_data)
        
        TASK_RESULTS[task_id] = {
            "status": "done",
            "action": "attack",
            "reason": "Enemy detected in zone A",
            "timestamp": time.time(),
        }
        
        logger.info(f"Task {task_id} completed successfully")
        
    except asyncio.CancelledError:
        logger.warning(f"Task {task_id} was cancelled")
        TASK_RESULTS[task_id] = {
            "status": "error",
            "action": None,
            "reason": "Task cancelled",
            "timestamp": time.time(),
        }
    except Exception as e:
        logger.exception(f"Unexpected error processing task {task_id}")
        TASK_RESULTS[task_id] = {
            "status": "error",
            "action": None,
            "reason": "Internal processing error",
            "timestamp": time.time(),
        }

# ----------------------------
# Health & Monitoring
# ----------------------------
START_TIME = time.time()

@app.get("/", tags=["meta"])
async def root():
    """Root endpoint with API information"""
    return {
        "name": "Game Automation Backend",
        "version": "2.0.0",
        "status": "operational",
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "send": "/send (POST, requires auth)",
            "result": "/result/{task_id} (GET, requires auth)",
        },
    }

@app.get("/health", response_model=HealthResponse, tags=["meta"])
@limiter.limit("60/minute")
async def health(request: Request):
    """Health check endpoint with metrics"""
    return HealthResponse(
        status="healthy",
        timestamp=time.time(),
        tasks_in_memory=len(TASK_RESULTS),
        uptime_seconds=time.time() - START_TIME,
    )

# ----------------------------
# API Endpoints
# ----------------------------
@app.post("/send", response_model=TaskResponse, tags=["queue"], dependencies=[Depends(verify_token)])
@limiter.limit("10/minute")
async def send_screenshot(
    request: Request,
    payload: ScreenPayload,
    background: BackgroundTasks,
):
    """
    Submit a screenshot for processing.
    Returns a task_id for polling results.
    
    Rate limit: 10 requests per minute per IP
    """
    # Cleanup old tasks before accepting new ones
    cleanup_old_tasks()
    
    # Check memory pressure
    if len(TASK_RESULTS) > 1000:
        logger.warning(f"High task count: {len(TASK_RESULTS)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="System is under heavy load. Please try again later."
        )
    
    task_id = str(uuid.uuid4())
    
    # Initialize task status
    TASK_RESULTS[task_id] = {
        "status": "processing",
        "action": None,
        "reason": None,
        "timestamp": time.time(),
    }
    
    # Queue background processing
    background.add_task(process_screenshot, task_id, payload.screenshot)
    
    logger.info(f"Task {task_id} queued")
    
    return TaskResponse(
        task_id=task_id,
        status="queued",
        message="Screenshot received and queued for processing"
    )

@app.get("/result/{task_id}", response_model=ResultResponse, tags=["queue"], dependencies=[Depends(verify_token)])
@limiter.limit("60/minute")
async def get_result(request: Request, task_id: str):
    """
    Poll for the result of a submitted task.
    
    Returns:
    - {"status": "processing"} - Task is still being processed
    - {"status": "done", "action": "...", ...} - Task completed successfully
    - {"status": "error", "reason": "..."} - Task failed
    
    Rate limit: 60 requests per minute per IP
    """
    # Validate UUID format
    try:
        uuid.UUID(task_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid task_id format"
        )
    
    result = TASK_RESULTS.get(task_id)
    
    if not result:
        # Task not found or expired
        return ResultResponse(
            status="not_found",
            reason="Task not found or has expired"
        )
    
    # Return result without removing (allow re-polling)
    # Only cleanup happens via TTL
    return ResultResponse(**result)

# ----------------------------
# Error Handlers
# ----------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler"""
    logger.warning(f"HTTP {exc.status_code}: {exc.detail} - {request.method} {request.url.path}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers,
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Catch-all exception handler"""
    logger.exception(f"Unhandled exception: {request.method} {request.url.path}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )

# ----------------------------
# Run Server (for local development)
# ----------------------------
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    
    logger.info(f"Starting server on {host}:{port}")
    
    uvicorn.run(
        "server:app",
        host=host,
        port=port,
        reload=os.getenv("ENVIRONMENT") == "development",
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )