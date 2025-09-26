def magic_link_html(token: str, fname: str) -> str:
    return f"""
    <html>
      <body>
        <h2>Welcome {fname},</h2>
        <p>Please click the link below to verify your email:</p>
        <a href="https://apis.solarad.ai/dashboard/auth/verifyEmail?token={token}">
          Verify Email
        </a>
      </body>
    </html>
    """


def reset_password_html(email: str, fname: str, token: str) -> str:
    return f"""
    <html>
      <body>
        <h2>Hello {fname},</h2>
        <p>Please click the link below to reset your password:</p>
        <a href="https://app.solarad.ai/resetPassword?email={email}&token={token}">
          Reset Password
        </a>
      </body>
    </html>
    """
