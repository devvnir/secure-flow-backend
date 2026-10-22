import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from dotenv import load_dotenv
import logging

from .routes import auth, data_flows
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

# Security middleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(data_flows.router)

@app.on_event("startup")
async def startup_event():
    logger.info("Initializing database")
    init_db()
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
