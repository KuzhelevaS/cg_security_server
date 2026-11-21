import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import Optional
from config import logger

class EmailNotifier:
    def __init__(self):
        self.host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.port = int(os.getenv("SMTP_PORT", "587"))
        self.user = os.getenv("SMTP_USER", "")
        self.password = os.getenv("SMTP_PASSWORD", "")
        self.sender = os.getenv("SMTP_FROM", self.user)
        self.use_tls = os.getenv("SMTP_TLS", "true").lower() in ("true", "1", "yes")

    def is_configured(self) -> bool:
        return bool(self.host and self.user and self.password)

    def send(self, recipient: str, subject: str, text_body: str, json_file_path: Optional[str] = None) -> bool:
        if not self.is_configured():
            logger.error("❌ SMTP не настроен. Проверь SMTP_HOST/USER/PASSWORD в .env")
            return False
        try:
            msg = MIMEMultipart()
            msg["From"] = self.sender
            msg["To"] = recipient
            msg["Subject"] = subject
            msg.attach(MIMEText(text_body, "plain", "utf-8"))
            
            if json_file_path and os.path.exists(json_file_path):
                with open(json_file_path, "rb") as f:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(f.read())
                encoders.encode_base64(part)
                filename = os.path.basename(json_file_path)
                part.add_header("Content-Disposition", f"attachment; filename={filename}")
                msg.attach(part)
                
            with smtplib.SMTP(self.host, self.port) as server:
                if self.use_tls: server.starttls()
                server.login(self.user, self.password)
                server.sendmail(self.sender, [recipient], msg.as_string())
            logger.info(f"📧 Email отправлен на {recipient}")
            return True
        except Exception as e:
            logger.error(f"❌ Ошибка отправки email: {e}")
            return False