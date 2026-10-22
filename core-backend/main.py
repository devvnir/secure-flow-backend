import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
import logging

from .routes import auth, data_flows, ingestion
from .database import init_db

load_dotenv()

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

# CORS configuration - MUST be first
cors_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
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
    error_msg = str(exc)
    logger.error(f"Unhandled exception: {error_msg}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": error_msg},
        headers={
            "Access-Control-Allow-Origin": "http://localhost:3000",
            "Access-Control-Allow-Credentials": "true",
        },
    )

# Include routers
app.include_router(auth.router)
app.include_router(data_flows.router)
app.include_router(ingestion.router)

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
