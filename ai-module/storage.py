import os
import json
from typing import Optional
from config import logger

class UserStorage:
    def __init__(self, storage_file: str = "users.json"):
        self.storage_file = storage_file
        self.users: dict[str, dict] = {}
        self._load()

    def _load(self):
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, 'r', encoding='utf-8') as f:
                    self.users = json.load(f)
                logger.info(f"📂 Загружено {len(self.users)} пользователей из {self.storage_file}")
            except Exception as e:
                logger.error(f"Ошибка загрузки users.json: {e}")

    def _save(self):
        try:
            with open(self.storage_file, 'w', encoding='utf-8') as f:
                json.dump(self.users, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Ошибка сохранения users.json: {e}")

    def add_user(self, chat_id: int, username: str, first_name: str) -> None:
        key = username or f"user_{chat_id}"
        self.users[key] = {
            "chat_id": chat_id,
            "username": username or "unknown",
            "first_name": first_name or "User"
        }
        self._save()
        logger.info(f"✅ Добавлен пользователь: {first_name} (@{username}), chat_id={chat_id}")

    def get_chat_id_by_username(self, username: str) -> Optional[int]:
        username_clean = username.lstrip("@").lower()
        for key, data in self.users.items():
            if key.lower() == username_clean or data.get("username", "").lower() == username_clean:
                return data["chat_id"]
        return None

    def list_users(self) -> list[dict]:
        return [{"username": key, **data} for key, data in self.users.items()]

def resolve_recipient(identifier: str, storage: UserStorage) -> Optional[int]:
    if not identifier:
        return None
    identifier = identifier.strip()
    if identifier.isdigit():
        return int(identifier)
    chat_id = storage.get_chat_id_by_username(identifier)
    if chat_id:
        return chat_id
    return None