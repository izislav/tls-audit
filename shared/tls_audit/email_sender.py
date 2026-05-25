import smtplib
from email.message import EmailMessage
from urllib.parse import urlparse


def send_email(
    *,
    smtp_url: str,
    smtp_user: str,
    smtp_password: str,
    mail_from: str,
    mail_to: str,
    subject: str,
    body: str,
) -> bool:
    if not smtp_url:
        return False
    parsed = urlparse(smtp_url)
    host = parsed.hostname
    port = parsed.port or (465 if parsed.scheme == "smtps" else 587)
    if not host:
        return False
    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = mail_to
    msg["Subject"] = subject
    msg.set_content(body)
    if parsed.scheme == "smtps":
        with smtplib.SMTP_SSL(host, port, timeout=20) as server:
            if smtp_user:
                server.login(smtp_user, smtp_password)
            server.send_message(msg)
        return True
    with smtplib.SMTP(host, port, timeout=20) as server:
        server.starttls()
        if smtp_user:
            server.login(smtp_user, smtp_password)
        server.send_message(msg)
    return True
