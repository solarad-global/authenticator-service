from fastapi import FastAPI, Request
from auth import auth_router
from logging_config import setup_logging
import logging

setup_logging()
logger = logging.getLogger("main")

app = FastAPI(title="Auth API - GCS CSV")
app.include_router(auth_router)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Incoming request: {request.method} {request.url}")
    response = await call_next(request)
    logger.info(f"Completed {request.method} {request.url} - Status {response.status_code}")
    return response

@app.get("/")
def root():
    logger.info("Root endpoint called")
    return {"message": "Auth API is running"}

@app.get("/health")
def health_check():
    logger.info("Health check called")
    return {"status": "ok"}
