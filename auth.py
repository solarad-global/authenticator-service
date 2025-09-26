from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse
import os, jwt, bcrypt, logging
from datetime import datetime, timedelta

from gcs_db import add_user, find_user, update_password
from mailer import send_magic_link_email, send_reset_password_link

logger = logging.getLogger("auth")

auth_router = APIRouter(prefix="/auth")

JWT_SECRET = os.getenv("JWT_SECRET", "changeme")
ADMIN_COMPANY = os.getenv("ADMIN_COMPANY", "ADMIN")
SUPERADMIN_COMPANY = os.getenv("SUPERADMIN_COMPANY", "SUPERADMIN")


@auth_router.get("/signUp")
def sign_up(email: str, fname: str, lname: str, pwd: str, company: str):
    logger.info(f"[SIGNUP] {email}, company={company}")
    if find_user(email):
        logger.warning(f"[SIGNUP] Duplicate email: {email}")
        return {"status": "Email Present", "detail": "User already exists"}

    token = jwt.encode(
        {
            "email": email,
            "fname": fname,
            "lname": lname,
            "pwd": pwd,
            "company": company,
            "exp": datetime.utcnow() + timedelta(hours=24),
        },
        JWT_SECRET,
        algorithm="HS256"
    )

    send_magic_link_email(email=email, token=token, fname=fname)
    logger.info(f"[SIGNUP] Magic link sent to {email}")
    return {"status": "Email Sent"}


@auth_router.get("/signIn")
def sign_in(email: str, pwd: str):
    logger.info(f"[SIGNIN] Attempt: {email}")
    user = find_user(email)
    if not user:
        logger.warning(f"[SIGNIN] User not found: {email}")
        return {"status": "Invalid credentials"}

    if not user.get("passhash"):
        logger.error(f"[SIGNIN] Corrupted record: {email}")
        raise HTTPException(status_code=500, detail="Corrupted user record")

    if bcrypt.checkpw(pwd.encode(), user["passhash"].encode()):
        logger.info(f"[SIGNIN] Success: {email} ({user['company']})")
        if user["company"] == ADMIN_COMPANY:
            return {"status": "Valid", "role": "Admin"}
        elif user["company"] == SUPERADMIN_COMPANY:
            return {"status": "Valid", "role": "Super_Admin"}
        return {"status": "Valid", "role": "User"}

    logger.warning(f"[SIGNIN] Wrong password: {email}")
    return {"status": "Invalid credentials"}


@auth_router.get("/verifyEmail")
def verify_email(token: str):
    logger.info("[VERIFYEMAIL] Token received")
    decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    add_user(
        email=decoded["email"],
        fname=decoded["fname"],
        lname=decoded["lname"],
        company=decoded["company"],
        password=decoded["pwd"]
    )
    logger.info(f"[VERIFYEMAIL] User verified: {decoded['email']}")
    return RedirectResponse(
        url=f"https://app.solarad.ai/emaillogin?email={decoded['email']}&password={decoded['pwd']}"
    )


@auth_router.get("/forgotPassword")
def forgot_password(email: str):
    logger.info(f"[FORGOT] Password reset requested: {email}")
    user = find_user(email)
    if not user:
        logger.warning(f"[FORGOT] Email not found: {email}")
        return {"status": "Invalid credentials"}

    token = jwt.encode({"email": email, "exp": datetime.utcnow() + timedelta(hours=1)},
                       JWT_SECRET, algorithm="HS256")

    send_reset_password_link(email=email, fname=user["fname"], token=token)
    logger.info(f"[FORGOT] Reset email sent: {email}")
    return {"status": "Email Sent"}


@auth_router.get("/resetPassword")
def reset_password(token: str, pwd: str):
    logger.info("[RESETPASS] Reset attempt")
    decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    update_password(decoded["email"], pwd)
    logger.info(f"[RESETPASS] Password updated: {decoded['email']}")
    return {"status": "Password Updated"}
