import csv
import io
import bcrypt
from datetime import datetime
from google.cloud import storage
import logging

logger = logging.getLogger("gcs_db")

BUCKET_NAME = "solarad-global-constant"
CSV_PATH = "dashboard_user/users.csv"

storage_client = storage.Client()

FIELDNAMES = ["ID", "User Email", "User Fname", "User Lname", "Company", "Passhash", "Created At"]


def download_csv():
    """Download CSV from GCS into memory"""
    logger.info(f"Downloading users CSV from gs://{BUCKET_NAME}/{CSV_PATH}")
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(CSV_PATH)
    try:
        if not blob.exists():
            logger.warning("CSV does not exist in GCS")
            return []
        content = blob.download_as_text()
        logger.info(f"Downloaded {len(content)} bytes from CSV")
        reader = csv.DictReader(io.StringIO(content))
        return list(reader)
    except Exception as e:
        logger.exception(f"Failed to download CSV: {e}")
        raise


def upload_csv(users, if_generation_match=None):
    """Upload updated CSV to GCS with concurrency check"""
    logger.info(f"Uploading {len(users)} users to GCS")
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(CSV_PATH)

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=FIELDNAMES)
    writer.writeheader()
    writer.writerows(users)

    try:
        if if_generation_match is not None:
            blob.upload_from_string(output.getvalue(), content_type="text/csv", if_generation_match=if_generation_match)
        else:
            blob.upload_from_string(output.getvalue(), content_type="text/csv")
    except Exception as e:
        logger.exception("Failed to upload CSV")
        raise


def find_user(email: str):
    logger.info(f"Looking up user {email}")
    users = download_csv()
    for user in users:
        if user["User Email"].lower() == email.lower():
            logger.info(f"User {email} found")
            return user
    logger.warning(f"User {email} not found")
    return None


def add_user(email: str, fname: str, lname: str, company: str, password: str):
    logger.info(f"Adding new user {email}")
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(CSV_PATH)

    if blob.exists():
        users = download_csv()
        gen = blob.generation
    else:
        users = []
        gen = 0

    if any(u["User Email"].lower() == email.lower() for u in users):
        logger.error(f"User {email} already exists")
        raise ValueError("User already exists")

    next_id = str(max([int(u["ID"]) for u in users] or [0]) + 1)
    passhash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    users.append({
        "ID": next_id,
        "User Email": email,
        "User Fname": fname,
        "User Lname": lname,
        "Company": company,
        "Passhash": passhash,
        "Created At": created_at
    })

    upload_csv(users, if_generation_match=gen)


def update_password(email: str, new_password: str):
    logger.info(f"Updating password for {email}")
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(CSV_PATH)

    if not blob.exists():
        raise ValueError("User not found")

    users = download_csv()
    gen = blob.generation

    updated = False
    for user in users:
        if user["User Email"].lower() == email.lower():
            user["Passhash"] = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            updated = True

    if not updated:
        raise ValueError("User not found")

    upload_csv(users, if_generation_match=gen)
