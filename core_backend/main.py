import os
import re
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
import logging

# Must run before importing modules that read env vars at import time.
load_dotenv()

from .routes import auth, data_flows, ingestion, mock_reso  # noqa: E402
from .database import init_db  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Secure Flow API",
    description="Secure data flow orchestration and management",
    version="1.0.0"
)

CORS_ORIGIN_REGEX = os.getenv("CORS_ORIGIN_REGEX", r"^http://(localhost|127\.0\.0\.1)(:\d+)?$")

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

# Security middleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

# Exception handler to ensure CORS headers are sent
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    headers = {}
    origin = request.headers.get("origin")
    if origin and re.match(CORS_ORIGIN_REGEX, origin):
        headers = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}
    return JSONResponse(status_code=500, content={"detail": "Internal server error"}, headers=headers)

# Include routers
app.include_router(auth.router)
app.include_router(data_flows.router)
app.include_router(ingestion.router)
app.include_router(mock_reso.router)

@app.on_event("startup")
async def startup_event():
    logger.info("Initializing database")
    try:
        init_db()
    except Exception as e:
        logger.warning(f"Database initialization failed: {e}. API will run in limited mode.")
    logger.info("Secure Flow API starting up")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Secure Flow API shutting down")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "secure-flow-api"}

@app.get("/")
async def root():
    return {
        "message": "Secure Flow API",
        "version": "1.0.0",
        "docs": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=os.getenv("API_HOST", "0.0.0.0"),
        port=int(os.getenv("API_PORT", 8000))
    )
