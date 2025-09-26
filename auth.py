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
    logger.info(f"[SIGNUP] Request: email={email}, company={company}, fname={fname}, lname={lname}")
    try:
        if find_user(email):
            logger.warning(f"[SIGNUP] Attempt with existing email: {email}")
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
        logger.info(f"[SIGNUP] Magic link email sent to {email}")
        return {"status": "Email Sent", "detail": "Verification email dispatched"}
    except Exception as e:
        logger.exception(f"[SIGNUP] Failed for {email}")
        raise HTTPException(status_code=500, detail=f"SignUp error: {str(e)}")


@auth_router.get("/signIn")
def sign_in(email: str, pwd: str):
    logger.info(f"[SIGNIN] Attempt: email={email}")
    try:
        user = find_user(email)
        if not user:
            logger.warning(f"[SIGNIN] User not found: {email}")
            return {"status": "Invalid credentials", "detail": "Email or password is incorrect"}

        stored_passhash = user.get("Passhash")
        if not stored_passhash:
            logger.error(f"[SIGNIN] Corrupted record for {email} (no Passhash)")
            raise HTTPException(status_code=500, detail="User record corrupted")

        if bcrypt.checkpw(pwd.encode(), stored_passhash.encode()):
            logger.info(f"[SIGNIN] Success: {email} ({user['Company']})")
            if user["Company"] == ADMIN_COMPANY:
                return {"status": "Valid", "role": "Admin"}
            elif user["Company"] == SUPERADMIN_COMPANY:
                return {"status": "Valid", "role": "Super_Admin"}
            return {"status": "Valid", "role": "User"}
        else:
            logger.warning(f"[SIGNIN] Wrong password for {email}")
            return {"status": "Invalid credentials", "detail": "Email or password is incorrect"}

    except Exception as e:
        logger.exception(f"[SIGNIN] Failure for {email}")
        raise HTTPException(status_code=500, detail=f"SignIn error: {str(e)}")


@auth_router.get("/verifyEmail")
def verify_email(token: str):
    logger.info("[VERIFYEMAIL] Verification attempt with token")
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        email = decoded["email"]
        logger.info(f"[VERIFYEMAIL] Token valid for {email}")

        add_user(
            email=email,
            fname=decoded["fname"],
            lname=decoded["lname"],
            company=decoded["company"],
            password=decoded["pwd"]
        )

        logger.info(f"[VERIFYEMAIL] User {email} created successfully")
        return RedirectResponse(
            url=f"https://app.solarad.ai/emaillogin?email={decoded['email']}&password={decoded['pwd']}"
        )
    except jwt.ExpiredSignatureError:
        logger.error("[VERIFYEMAIL] Token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception as e:
        logger.exception("[VERIFYEMAIL] General failure")
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@auth_router.get("/forgotPassword")
def forgot_password(email: str):
    logger.info(f"[FORGOT] Password reset requested for {email}")
    try:
        user = find_user(email)
        if not user:
            logger.warning(f"[FORGOT] Email not found: {email}")
            return {"status": "Invalid credentials", "detail": "Email not registered"}

        token = jwt.encode(
            {"email": email, "exp": datetime.utcnow() + timedelta(hours=1)},
            JWT_SECRET,
            algorithm="HS256"
        )

        send_reset_password_link(email=email, fname=user["User Fname"], token=token)
        logger.info(f"[FORGOT] Reset email sent to {email}")
        return {"status": "Email Sent", "detail": "Password reset email dispatched"}
    except Exception as e:
        logger.exception(f"[FORGOT] Failed for {email}")
        raise HTTPException(status_code=500, detail=f"ForgotPassword error: {str(e)}")


@auth_router.get("/resetPassword")
def reset_password(token: str, pwd: str):
    logger.info("[RESETPASS] Password reset attempt with token")
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        email = decoded["email"]
        logger.info(f"[RESETPASS] Token valid for {email}")
        update_password(email, pwd)
        logger.info(f"[RESETPASS] Password updated for {email}")
        return {"status": "Password Updated", "detail": "Password reset successful"}
    except jwt.ExpiredSignatureError:
        logger.error("[RESETPASS] Token expired")
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception as e:
        logger.exception("[RESETPASS] General failure")
        raise HTTPException(status_code=500, detail=f"ResetPassword error: {str(e)}")
