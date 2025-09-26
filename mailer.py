import os
import smtplib
from email.mime.text import MIMEText
from html_content import magic_link_html, reset_password_html
import logging

logger = logging.getLogger("mailer")

SMTP_HOST = os.getenv("BREVO_HOST")
SMTP_PORT = int(os.getenv("BREVO_PORT", 587))
SMTP_USER = os.getenv("BREVO_USER")
SMTP_PASS = os.getenv("BREVO_PWD")
FROM_EMAIL = os.getenv("FROM_EMAIL")


def send_magic_link_email(email: str, token: str, fname: str):
    html = magic_link_html(token, fname)
    msg = MIMEText(html, "html")
    msg["Subject"] = "Finish Logging In"
    msg["From"] = FROM_EMAIL
    msg["To"] = email

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(FROM_EMAIL, [email], msg.as_string())
        logger.info(f"Magic link email sent to {email}")
    except Exception as e:
        logger.exception("Failed to send magic link email")
        raise


def send_reset_password_link(email: str, fname: str, token: str):
    html = reset_password_html(email, fname, token)
    msg = MIMEText(html, "html")
    msg["Subject"] = "Reset Your Password"
    msg["From"] = FROM_EMAIL
    msg["To"] = email

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(FROM_EMAIL, [email], msg.as_string())
        logger.info(f"Password reset email sent to {email}")
    except Exception as e:
        logger.exception("Failed to send reset password email")
        raise
