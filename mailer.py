import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

from html_content import magic_link_html, reset_password_html

logger = logging.getLogger("mailer")

SMTP_HOST = os.getenv("BREVO_HOST")
SMTP_PORT = int(os.getenv("BREVO_PORT", "587"))
SMTP_USER = os.getenv("BREVO_USER")
SMTP_PASS = os.getenv("BREVO_PWD")
FROM_EMAIL = os.getenv("FROM_EMAIL", "no-reply@solarad.ai")


def send_magic_link_email(email, token, fname):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Finish Logging In"
    msg["From"] = FROM_EMAIL
    msg["To"] = email
    html = magic_link_html(token, fname)
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(FROM_EMAIL, email, msg.as_string())
        logger.info(f"[MAILER] Magic link sent to {email}")
    except Exception as e:
        logger.exception(f"[MAILER] Failed to send magic link to {email}")


def send_reset_password_link(email, fname, token):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Reset Your Password"
    msg["From"] = FROM_EMAIL
    msg["To"] = email
    html = reset_password_html(email, fname, token)
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(FROM_EMAIL, email, msg.as_string())
        logger.info(f"[MAILER] Reset password link sent to {email}")
    except Exception as e:
        logger.exception(f"[MAILER] Failed to send reset password to {email}")
