from fastapi import FastAPI
from auth import auth_router
from logging_config import setup_logging
import logging

# Initialize logging
setup_logging()
logger = logging.getLogger("main")

app = FastAPI(title="Authenticator Service")

# Register routes
app.include_router(auth_router)


@app.get("/")
def root():
    logger.info("Root endpoint called")
    return {"message": "Authenticator Service is running"}
