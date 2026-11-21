"""
Публикация отчётов в Telegraph (telegra.ph).
Бесплатно, без сервера, работает из РФ.
"""
import os
import re
import httpx
from datetime import datetime
from config import logger


class TelegraphPublisher:
    def __init__(self):
        self.api_url = "https://api.telegra.ph"
        self.access_token = os.getenv("TELEGRAPH_ACCESS_TOKEN")
        self.account_name = "Cyber Garden"
        self.short_name = "cybergarden"

    async def _ensure_account(self):
        """Создаёт аккаунт Telegraph, если его нет."""
        if self.access_token:
            return
        
        logger.info("📝 Создаём аккаунт Telegraph...")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.api_url}/createAccount",
                data={
                    "short_name": self.short_name,
                    "author_name": self.account_name,
                    "author_url": "https://github.com/cybergarden"
                }
            )
            resp.raise_for_status()
            result = resp.json()
            
            if result.get("ok"):
                self.access_token = result["result"]["access_token"]
                logger.info(f"✅ Аккаунт Telegraph создан. Токен: {self.access_token[:20]}...")
                logger.info(f"💡 Добавь в .env: TELEGRAPH_ACCESS_TOKEN={self.access_token}")
            else:
                raise Exception(f"Ошибка создания аккаунта: {result}")

    def _text_to_telegraph_nodes(self, text: str) -> list:
        """Конвертирует текстовый отчёт в формат Telegraph."""
        nodes = []
        paragraphs = re.split(r'\n\n+', text.strip())
        
        for para in paragraphs:
            if para.startswith("🔍") or para.startswith("━"):
                nodes.append({
                    "tag": "h3",
                    "children": [para.replace("━", "").strip()]
                })
            elif para.startswith("🔴") or para.startswith("🟠") or para.startswith("🟡") or para.startswith("🟢"):
                nodes.append({
                    "tag": "p",
                    "children": [{"tag": "b", "children": [para]}]
                })
            elif para.startswith("📁") or para.startswith("🆔") or para.startswith("⚠️") or para.startswith("💡"):
                nodes.append({
                    "tag": "p",
                    "children": [para]
                })
            else:
                lines = para.split('\n')
                children = []
                for i, line in enumerate(lines):
                    if i > 0:
                        children.append({"tag": "br"})
                    children.append(line)
                if children:
                    nodes.append({
                        "tag": "p",
                        "children": children
                    })
        
        return nodes

    async def publish_report(self, run_id: str, text_report: str, summary: str, findings_count: int) -> str:
        """Публикует отчёт в Telegraph и возвращает URL."""
        await self._ensure_account()
        
        date_str = datetime.now().strftime("%d-%m-%Y")
        title = f"Cyber Garden — Отчёт {date_str} ({findings_count} находок)"
        
        content_nodes = self._text_to_telegraph_nodes(text_report)
        
        meta_nodes = [
            {
                "tag": "p",
                "children": [
                    {"tag": "b", "children": ["Run ID: "]},
                    run_id,
                    {"tag": "br"},
                    {"tag": "b", "children": ["Дата: "]},
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    {"tag": "br"},
                    {"tag": "b", "children": ["Всего находок: "]},
                    str(findings_count)
                ]
            },
            {"tag": "hr"},
            {
                "tag": "h4",
                "children": ["Краткое саммари"]
            },
            {
                "tag": "p",
                "children": [summary]
            },
            {"tag": "hr"},
            {
                "tag": "h4",
                "children": ["Полный отчёт"]
            }
        ]
        
        full_content = meta_nodes + content_nodes
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.api_url}/createPage",
                data={
                    "access_token": self.access_token,
                    "title": title,
                    "content": str(full_content).replace("'", '"'),
                    "return_content": "false"
                }
            )
            resp.raise_for_status()
            result = resp.json()
            
            if result.get("ok"):
                url = result["result"]["url"]
                logger.info(f"🌐 Отчёт опубликован: {url}")
                return url
            else:
                raise Exception(f"Ошибка публикации: {result}")