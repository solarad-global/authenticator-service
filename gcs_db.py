import os, json, logging
from google.cloud import storage
import bcrypt
from datetime import datetime

logger = logging.getLogger("gcs_db")

BUCKET_NAME = "solarad-global-constant"
JSON_PATH = "dashboard_user/users.json"

storage_client = storage.Client()


def download_users():
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(JSON_PATH)
    try:
        if not blob.exists():
            logger.warning(f"users.json not found in gs://{BUCKET_NAME}/{JSON_PATH}")
            return []
        data = blob.download_as_text()
        logger.info(f"Loaded {len(data)} bytes from users.json")
        return json.loads(data)
    except Exception as e:
        logger.exception("Failed to download users.json")
        return []


def upload_users(users):
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(JSON_PATH)
    try:
        blob.upload_from_string(json.dumps(users, indent=2), content_type="application/json")
        logger.info(f"Uploaded {len(users)} users to users.json")
    except Exception as e:
        logger.exception("Failed to upload users.json")


def find_user(email):
    users = download_users()
    for u in users:
        if u["email"].lower() == email.lower():
            return u
    return None


def add_user(email, fname, lname, company, password):
    users = download_users()
    if find_user(email):
        logger.warning(f"User {email} already exists")
        return
    passhash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    new_user = {
        "email": email,
        "fname": fname,
        "lname": lname,
        "company": company,
        "passhash": passhash,
        "created_at": datetime.utcnow().isoformat()
    }
    users.append(new_user)
    upload_users(users)
    logger.info(f"Added user {email}")


def update_password(email, password):
    users = download_users()
    for u in users:
        if u["email"].lower() == email.lower():
            u["passhash"] = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            u["updated_at"] = datetime.utcnow().isoformat()
            upload_users(users)
            logger.info(f"Updated password for {email}")
            return
    logger.warning(f"Tried to update password for non-existent {email}")
