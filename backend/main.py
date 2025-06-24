from fastapi import FastAPI, Request, Response
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from backend.api.routes import router
import uvicorn
import os
import logging
import time
from datetime import datetime, timezone
import psutil
import platform
from backend.utils.monitoring import monitoring_service
from fastapi import HTTPException
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response
from backend.utils.database import initialize_database
from backend.utils.monitoring import setup_monitoring
from backend.services.virustotal import virustotal_service
from backend.utils.exceptions import PhishingAppException, create_error_response
from backend.utils.logging_config import setup_structured_logging, get_logger, generate_correlation_id, set_correlation_id
from backend.utils.security import validate_secret_key

# Setup structured logging
setup_structured_logging()
logger = get_logger(__name__)

# Prometheus metrics
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint', 'status'])
REQUEST_LATENCY = Histogram('http_request_duration_seconds', 'HTTP request latency')
ACTIVE_CONNECTIONS = Gauge('active_connections', 'Number of active connections')
SYSTEM_MEMORY = Gauge('system_memory_usage_bytes', 'System memory usage in bytes')
SYSTEM_CPU = Gauge('system_cpu_usage_percent', 'System CPU usage percentage')

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting Phishing Detection API...")
    
    # Initialize database
    try:
        await initialize_database()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Service error in database_initialization: {type(e).__name__}")
        raise
    
    # Configure VirusTotal service
    try:
        vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if vt_api_key:
            virustotal_service.configure(vt_api_key)
            logger.info("VirusTotal service configured successfully")
        else:
            logger.warning("VIRUSTOTAL_API_KEY not found - VirusTotal features will be disabled")
    except Exception as e:
        logger.error(f"Service error in virustotal_configuration: {type(e).__name__}")
        raise
    
    # Setup monitoring
    setup_monitoring()
    logger.info("Monitoring setup completed")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Phishing Detection API...")
    try:
        await virustotal_service.close_session()
        logger.info("VirusTotal session closed")
    except Exception as e:
        logger.error(f"Service error in virustotal_cleanup: {type(e).__name__}")

app = FastAPI(
    title="Phishing Email Detection API",
    description="A secure micro SaaS for phishing email detection with VirusTotal integration",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Frontend URLs
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

# Add trusted host middleware for security
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Configure appropriately for production
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Get rate limit configuration from environment
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
RATE_LIMIT_AUTH_PER_MINUTE = int(os.getenv("RATE_LIMIT_AUTH_PER_MINUTE", "5"))

# Correlation ID middleware
@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    """Add correlation ID to each request for tracing"""
    correlation_id = generate_correlation_id()
    set_correlation_id(correlation_id)
    
    # Add correlation ID to request state
    request.state.correlation_id = correlation_id
    
    # Process request
    response = await call_next(request)
    
    # Add correlation ID to response headers
    response.headers["X-Correlation-ID"] = correlation_id
    
    return response

# JWT configuration
@AuthJWT.load_config
def get_config():
    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        # Use a default for development, but warn
        secret_key = "development_secret_key_change_in_production_environment"
        logger.warning("SECRET_KEY not set, using development default. Change this in production!")
    
    # Only validate if we have a real secret key (not the default)
    if secret_key != "development_secret_key_change_in_production_environment":
        try:
            if not validate_secret_key(secret_key):
                logger.warning("SECRET_KEY does not meet security requirements. Using anyway but please fix.")
        except Exception as e:
            logger.warning(f"Secret key validation failed: {e}. Using anyway.")
    
    return [
        ("authjwt_secret_key", secret_key),
        ("authjwt_algorithm", os.getenv("ALGORITHM", "HS256")),
        ("authjwt_access_token_expires", int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30)) * 60),
        ("authjwt_token_location", ["headers"]),
        ("authjwt_cookie_csrf_protect", False),
    ]

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request, exc):
    correlation_id = getattr(request.state, 'correlation_id', 'no-correlation-id')
    logger.warning(
        "JWT authentication error",
        correlation_id=correlation_id,
        error=exc.message,
        status_code=exc.status_code
    )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    # Get correlation ID from request state
    correlation_id = getattr(request.state, 'correlation_id', 'no-correlation-id')
    
    # Increment request counter
    monitoring_service.increment_request_count()
    
    # Log request with structured data
    logger.info(
        "Request started",
        correlation_id=correlation_id,
        method=request.method,
        endpoint=request.url.path,
        client_ip=request.client.host if request.client else 'unknown',
        user_agent=request.headers.get('user-agent', 'unknown')
    )
    
    # Process request
    response = await call_next(request)
    
    # Log response with structured data
    process_time = time.time() - start_time
    logger.info(
        "Request completed",
        correlation_id=correlation_id,
        method=request.method,
        endpoint=request.url.path,
        status_code=response.status_code,
        duration=process_time,
        client_ip=request.client.host if request.client else 'unknown'
    )
    
    # Increment error counter if response is an error
    if response.status_code >= 400:
        monitoring_service.increment_error_count()
        logger.warning(
            "Request error",
            correlation_id=correlation_id,
            method=request.method,
            endpoint=request.url.path,
            status_code=response.status_code,
            duration=process_time
        )
    
    # Add custom headers
    response.headers["X-Process-Time"] = str(process_time)
    response.headers["X-Server-Time"] = datetime.now(timezone.utc).isoformat()
    
    return response

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Check database health
        db_health = monitoring_service.check_database_health()
        
        # Basic system info
        system_info = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0",
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "uptime": monitoring_service.get_uptime()
        }
        
        # Check critical services
        checks = {
            "database": db_health["status"],
            "virustotal_api": "healthy" if os.getenv('VIRUSTOTAL_API_KEY') else "not_configured"
        }
        
        system_info["services"] = checks
        
        # Determine overall health
        if all(check == "healthy" for check in checks.values()):
            system_info["status"] = "healthy"
        else:
            system_info["status"] = "degraded"
            
        logger.info("Health check completed successfully", status=system_info["status"])
        return system_info
        
    except Exception as e:
        logger.error(f"Service error in health_check: {type(e).__name__}")
        return JSONResponse(
            status_code=500,
            content={"status": "unhealthy", "error": "Health check failed"}
        )

# Metrics endpoint
@app.get("/metrics")
async def get_metrics():
    """Basic metrics endpoint for monitoring"""
    try:
        metrics = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "system": {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent,
                "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
            },
            "process": {
                "pid": os.getpid(),
                "memory_info": dict(psutil.Process().memory_info()._asdict()),
                "cpu_percent": psutil.Process().cpu_percent()
            },
            "application": monitoring_service.get_statistics(),
            "database": monitoring_service.check_database_health()
        }
        
        logger.debug("Metrics collected successfully")
        return metrics
        
    except Exception as e:
        logger.error(f"Service error in metrics_collection: {type(e).__name__}")
        return JSONResponse(
            status_code=500,
            content={"error": "Failed to collect metrics"}
        )

# Request/Response middleware for monitoring
@app.middleware("http")
async def monitoring_middleware(request: Request, call_next):
    """Middleware for request monitoring and metrics collection"""
    start_time = time.time()
    
    # Update active connections
    ACTIVE_CONNECTIONS.inc()
    
    # Update system metrics
    SYSTEM_MEMORY.set(psutil.virtual_memory().used)
    SYSTEM_CPU.set(psutil.cpu_percent())
    
    try:
        response = await call_next(request)
        
        # Record metrics
        duration = time.time() - start_time
        REQUEST_LATENCY.observe(duration)
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status=response.status_code
        ).inc()
        
        return response
        
    except Exception as e:
        # Record error metrics
        duration = time.time() - start_time
        REQUEST_LATENCY.observe(duration)
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            status=500
        ).inc()
        raise
    finally:
        # Decrease active connections
        ACTIVE_CONNECTIONS.dec()

# Global exception handler for standardized error responses
@app.exception_handler(PhishingAppException)
async def phishing_app_exception_handler(request: Request, exc: PhishingAppException):
    """Handle PhishingAppException with standardized error response"""
    correlation_id = getattr(request.state, 'correlation_id', 'no-correlation-id')
    logger.error(
        "PhishingAppException occurred",
        correlation_id=correlation_id,
        error_code=exc.error_code,
        error_message=exc.message,
        status_code=exc.status_code,
        endpoint=request.url.path,
        method=request.method
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=create_error_response(exc)
    )

# Global exception handler for other exceptions
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all other exceptions with standardized error response"""
    correlation_id = getattr(request.state, 'correlation_id', 'no-correlation-id')
    logger.error(
        "Unhandled exception occurred",
        correlation_id=correlation_id,
        error=str(exc),
        error_type=type(exc).__name__,
        endpoint=request.url.path,
        method=request.method,
        exc_info=True
    )
    
    # Create a generic error response
    error_response = {
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected error occurred",
            "status_code": 500,
            "context": {
                "endpoint": request.url.path,
                "method": request.method
            }
        }
    }
    
    return JSONResponse(
        status_code=500,
        content=error_response
    )

# Include router with rate limiting applied
app.include_router(router)

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
