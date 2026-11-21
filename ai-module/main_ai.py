"""
Точка входа AI-модуля Cyber Garden 2026.

Поддерживает два режима работы:
1. Программный вызов — бэкенд импортирует функцию analyze_findings() и передаёт JSON.
2. CLI (командная строка) — для твоих тестов и демо через main_ai().

Режимы CLI:
  python main_ai.py                                    # запуск Telegram-бота
  python main_ai.py --mock [@user]                     # тест Telegram
  python main_ai.py --mock-email user@example.com      # тест Email
  python main_ai.py --quick                            # быстрый тест AI
  python main_ai.py --list-users                       # список пользователей
"""
import sys
import asyncio
import os
import json
from config import logger
from storage import UserStorage
from telegram_bot import TelegramBot
from email_notifier import EmailNotifier
from ai_analyzer import AIAnalyzer
from orchestrator import Orchestrator


# ============================================
# 🚀 ГЛАВНАЯ ФУНКЦИЯ ДЛЯ ВЫЗОВА ИЗ БЭКЕНДА
# ============================================
async def analyze_findings(
    findings: dict,
    channel: str = "telegram",
    recipient: str = None,
    provider: str = None,
    run_id: str = "backend-run-001"
) -> dict:
    """
    Функция, которую вызывает бэкенд. Принимает JSON с находками и возвращает результаты.
    
    Параметры:
        findings: dict с находками от сканеров (валидируется внутри Orchestrator)
        channel: "telegram" или "email"
        recipient: username (с @ или без), chat_id (строкой) или email
        provider: "yandex" или "ollama" (если None, берётся из .env)
        run_id: уникальный идентификатор запуска
    
    Возвращает:
        dict с результатами:
        {
            "run_id": str,
            "summary": str,
            "text_report": str,
            "json_report": dict,
            "report_url": str | None,
            "findings_count": int
        }
    """
    logger.info(f"🔌 Вызов из бэкенда: run_id={run_id}, channel={channel}")
    
    storage = UserStorage()
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    tg_bot = TelegramBot(token, storage) if token else None
    
    analyzer = AIAnalyzer(provider=provider)
    
    # ⚠️ debug=False критически важен! Иначе бэкенд будет спамить в свои логи консольным выводом
    orchestrator = Orchestrator(
        analyzer=analyzer,
        storage=storage,
        tg_bot=tg_bot,
        email_notifier=EmailNotifier(),
        channel=channel,
        recipient=recipient,
        debug=False
    )
    
    # Запускаем workflow с реальными данными от бэкенда
    result = await orchestrator.run(run_id=run_id, raw_findings=findings)
    return result


# ============================================
# 🧪 ФУНКЦИИ ДЛЯ CLI-ТЕСТИРОВАНИЯ (ТВОИ ТЕСТЫ)
# ============================================
def run_bot():
    """Запуск Telegram-бота (основной режим)."""
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        logger.error("TELEGRAM_BOT_TOKEN не установлен в .env")
        return
    storage = UserStorage()
    bot = TelegramBot(token, storage)
    bot.run()


async def run_mock(channel: str = "telegram", recipient: str = None):
    """Тест с отправкой в Telegram или Email (использует заглушки)."""
    storage = UserStorage()
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    tg_bot = TelegramBot(token, storage) if token else None
    
    orchestrator = Orchestrator(
        analyzer=AIAnalyzer(),
        storage=storage,
        tg_bot=tg_bot,
        email_notifier=EmailNotifier(),
        channel=channel,
        recipient=recipient,
        debug=True  # Для тестов печать в консоль включена
    )
    await orchestrator.run("mock-001")


async def run_quick():
    """Быстрый тест AI без отправки куда-либо."""
    analyzer = AIAnalyzer()
    from mocks import MockBackend
    all_findings = MockBackend.get_all_findings()
    
    print("\n" + "═" * 70)
    print(f"🧪 БЫСТРЫЙ ТЕСТ AI (провайдер: {analyzer.provider})")
    print(f"Всего находок: {len(all_findings)}")
    print("═" * 70)
    
    reports = await analyzer.analyze_and_return(all_findings)
    
    print("\n📝 SUMMARY (для Telegram):")
    print("-" * 70)
    print(reports["summary"])
    
    print("\n📄 FULL TEXT (для Telegraph):")
    print("-" * 70)
    print(reports["text"])
    
    print("\n📦 JSON (для интеграции):")
    print("-" * 70)
    print(json.dumps(reports["json"], ensure_ascii=False, indent=2))
    
    with open("report_quick.json", 'w', encoding='utf-8') as f:
        json.dump(reports["json"], f, ensure_ascii=False, indent=2)
    
    print("\n💾 JSON сохранён в report_quick.json")
    print("\n" + "═" * 70 + "\n✅ ТЕСТ ЗАВЕРШЁН\n" + "═" * 70)


# ============================================
# 🎛️ CLI-ОБЁРТКА (твоя функция main_ai)
# ============================================
def main_ai():
    """Обработчик аргументов командной строки для тестирования."""
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "--mock":
            recipient = sys.argv[2] if len(sys.argv) > 2 else None
            asyncio.run(run_mock(channel="telegram", recipient=recipient))
        elif cmd == "--mock-email":
            recipient = sys.argv[2] if len(sys.argv) > 2 else os.getenv("SMTP_RECIPIENT", "")
            if not recipient:
                print("Использование: python main_ai.py --mock-email user@example.com")
                sys.exit(1)
            asyncio.run(run_mock(channel="email", recipient=recipient))
        elif cmd == "--quick":
            asyncio.run(run_quick())
        elif cmd == "--list-users":
            storage = UserStorage()
            users = storage.list_users()
            if not users:
                print("📭 Нет зарегистрированных пользователей.")
            else:
                print(f"\n📋 Пользователи ({len(users)}):\n")
                for u in users:
                    print(f"  • @{u['username']} — chat_id: {u['chat_id']}")
        else:
            print("Использование:")
            print("  python main_ai.py                                    # запуск бота")
            print("  python main_ai.py --mock [@user]                     # тест Telegram")
            print("  python main_ai.py --mock-email user@example.com      # тест Email")
            print("  python main_ai.py --quick                            # быстрый тест")
            print("  python main_ai.py --list-users                       # список пользователей")
    else:
        run_bot()


if __name__ == "__main__":
    main_ai()