import os
import asyncio
from telegram import Update, Bot
from telegram.ext import Application, CommandHandler, ContextTypes
from telegram.request import HTTPXRequest
from config import logger
from storage import UserStorage

class TelegramBot:
    def __init__(self, token: str, storage: UserStorage, proxy_url: str = None):
        self.token = token
        self.storage = storage
        self.proxy_url = proxy_url or os.getenv("TELEGRAM_PROXY")
        self._bot_instance = None

    def _get_bot(self) -> Bot:
        if self._bot_instance is None:
            kwargs = {"connect_timeout": 30.0, "read_timeout": 30.0, "write_timeout": 30.0, "pool_timeout": 30.0}
            if self.proxy_url:
                kwargs["proxy"] = self.proxy_url
            self._bot_instance = Bot(token=self.token, request=HTTPXRequest(**kwargs))
        return self._bot_instance

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = update.effective_user
        chat_id = update.effective_chat.id
        username = user.username
        first_name = user.first_name
        self.storage.add_user(chat_id=chat_id, username=username, first_name=first_name)
        await update.message.reply_text(
            f"👋 Привет, {first_name}!\n\n✅ Вы зарегистрированы в Cyber Garden.\n\n"
            f"📋 Ваш chat_id: {chat_id}\n👤 Ваш username: @{username or 'не задан'}\n\n"
            f"Используйте username (@{username or 'user_' + str(chat_id)}) или chat_id ({chat_id}) в настройках."
        )

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text("🤖 Cyber Garden Bot\n\n/start — регистрация\n/help — справка\n/users — список")

    async def users_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        users = self.storage.list_users()
        if not users:
            await update.message.reply_text("📭 Пока нет зарегистрированных пользователей.")
            return
        lines = ["📋 Зарегистрированные пользователи:\n"]
        for u in users:
            lines.append(f"• @{u['username']} — chat_id: {u['chat_id']} ({u['first_name']})")
        await update.message.reply_text("\n".join(lines))

    async def send_message(self, chat_id: int, text: str, parse_mode: str = None) -> bool:
        try:
            kwargs = {"chat_id": chat_id, "text": text}
            if parse_mode:
                kwargs["parse_mode"] = parse_mode
            await self._get_bot().send_message(**kwargs)
            return True
        except Exception as e:
            logger.error(f"Ошибка отправки в Telegram: {e}")
            return False

    async def send_long(self, chat_id: int, text: str, chunk_size: int = 3800):
        if len(text) <= chunk_size:
            return await self.send_message(chat_id, text)
        chunks, current = [], ""
        for paragraph in text.split("\n\n"):
            if len(current) + len(paragraph) + 2 > chunk_size:
                if current: chunks.append(current)
                current = paragraph
            else:
                current += ("\n\n" + paragraph) if current else paragraph
        if current: chunks.append(current)
        for i, chunk in enumerate(chunks, 1):
            prefix = f"(продолжение {i}/{len(chunks)})\n\n" if i > 1 else ""
            await self.send_message(chat_id, prefix + chunk)
            await asyncio.sleep(0.5)

    async def send_document(self, chat_id: int, file_path: str, caption: str = "") -> bool:
        try:
            with open(file_path, 'rb') as f:
                await self._get_bot().send_document(chat_id=chat_id, document=f, caption=caption if caption else None)
            logger.info(f"📎 Файл {file_path} отправлен в chat_id {chat_id}")
            return True
        except Exception as e:
            logger.error(f"Ошибка отправки файла: {e}")
            return False

    def run(self):
        kwargs = {"connect_timeout": 30.0, "read_timeout": 30.0}
        if self.proxy_url: kwargs["proxy"] = self.proxy_url
        app = Application.builder().token(self.token).request(HTTPXRequest(**kwargs)).build()
        app.add_handler(CommandHandler("start", self.start_command))
        app.add_handler(CommandHandler("help", self.help_command))
        app.add_handler(CommandHandler("users", self.users_command))
        logger.info("🤖 Telegram-бот запущен. Ожидание /start...")
        app.run_polling(allowed_updates=["message"], drop_pending_updates=True)