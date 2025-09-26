from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse
import os, jwt, bcrypt, logging
from datetime import datetime, timedelta

from gcs_db import add_user, find_user, update_password
from mailer import send_magic_link_email, send_reset_password_link

logger = logging.getLogger("auth")

auth_router = APIRouter(prefix="/auth")

JWT_SECRET = os.getenv("JWT_SECRET")
ADMIN_COMPANY = os.getenv("ADMIN_COMPANY")
SUPERADMIN_COMPANY = os.getenv("SUPERADMIN_COMPANY")


@auth_router.get("/signUp")
def sign_up(email: str, fname: str, lname: str, pwd: str, company: str):
    logger.info(f"SignUp request for {email} ({company})")
    if find_user(email):
        return {"status": "Email Present"}

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
    logger.info(f"Magic link sent to {email}")
    return {"status": "Email Sent"}


@auth_router.get("/signIn")
def sign_in(email: str, pwd: str):
    logger.info(f"SignIn attempt for {email}")
    user = find_user(email)
    if not user:
        return {"status": "Email Not Present"}

    stored_passhash = user["Passhash"]

    if bcrypt.checkpw(pwd.encode(), stored_passhash.encode()):
        logger.info(f"Password match for {email}")
        if user["Company"] == ADMIN_COMPANY:
            return {"status": "Admin"}
        elif user["Company"] == SUPERADMIN_COMPANY:
            return {"status": "Super_Admin"}
        return {"status": "Valid"}
    else:
        logger.warning(f"Invalid password for {email}")
        raise HTTPException(status_code=401, detail="Invalid")


@auth_router.get("/verifyEmail")
def verify_email(token: str):
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        logger.info(f"Verifying email for {decoded['email']}")

        add_user(
            email=decoded["email"],
            fname=decoded["fname"],
            lname=decoded["lname"],
            company=decoded["company"],
            password=decoded["pwd"]
        )

        return RedirectResponse(
            url=f"https://app.solarad.ai/emaillogin?email={decoded['email']}&password={decoded['pwd']}"
        )
    except jwt.ExpiredSignatureError:
        logger.error("Verification token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception as e:
        logger.exception("Email verification failed")
        raise HTTPException(status_code=500, detail=str(e))


@auth_router.get("/forgotPassword")
def forgot_password(email: str):
    logger.info(f"Forgot password request for {email}")
    user = find_user(email)
    if not user:
        return {"status": "Email Not Present"}

    token = jwt.encode(
        {"email": email, "exp": datetime.utcnow() + timedelta(hours=1)},
        JWT_SECRET,
        algorithm="HS256"
    )

    send_reset_password_link(email=email, fname=user["User Fname"], token=token)
    logger.info(f"Password reset email sent to {email}")
    return {"status": "Email Sent"}


@auth_router.get("/resetPassword")
def reset_password(token: str, pwd: str):
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        logger.info(f"Resetting password for {decoded['email']}")
        update_password(decoded["email"], pwd)
        return {"status": "Password Updated"}
    except jwt.ExpiredSignatureError:
        logger.error("Reset token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception as e:
        logger.exception("Password reset failed")
        raise HTTPException(status_code=500, detail=str(e))
