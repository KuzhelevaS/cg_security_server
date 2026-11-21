"""
Оркестратор Cyber Garden 2026.
Связывает все модули воедино:
  - Получает находки от бэкенда (реальные данные или заглушки MockBackend)
  - Передаёт в AI-анализатор
  - Публикует полный отчёт в Telegraph
  - Отправляет короткий summary + ссылку в Telegram или Email
  - Сохраняет JSON на диск (для интеграции в дашборды)

ВАЖНО: данные от бэкенда/фронта считаем корректными, валидация не нужна.

ФЛАГИ:
  - debug=True  → режим разработки: печатает отчёты в консоль (MockFrontend)
  - debug=False → продакшн-режим: бэкендер импортирует модуль, мусор в логах не нужен
"""
import json
from typing import Optional
from config import logger
from storage import UserStorage, resolve_recipient
from telegram_bot import TelegramBot
from email_notifier import EmailNotifier
from ai_analyzer import AIAnalyzer
from mocks import MockBackend, MockFrontend, IS_MOCK
from telegraph_publisher import TelegraphPublisher


class Orchestrator:
    def __init__(
        self,
        analyzer: AIAnalyzer,
        storage: UserStorage,
        tg_bot: Optional[TelegramBot] = None,
        email_notifier: Optional[EmailNotifier] = None,
        channel: str = "telegram",
        recipient: Optional[str] = None,
        debug: bool = True,  # 🚩 ФЛАГ: True = демо-режим с печатью, False = продакшн
    ):
        self.analyzer = analyzer
        self.storage = storage
        self.tg_bot = tg_bot
        self.email_notifier = email_notifier or EmailNotifier()
        self.channel = channel.lower()
        self.recipient = recipient
        self.telegraph = TelegraphPublisher()
        self.debug = debug  # 🚩 Сохраняем флаг

        if self.debug:
            logger.info("🧪 Orchestrator запущен в DEBUG-режиме (печать в консоль включена)")
        else:
            logger.info("🏭 Orchestrator запущен в PRODUCTION-режиме (печать в консоль отключена)")

    async def run(self, run_id: str = "demo-001", raw_findings: dict = None):
        """
        Запускает workflow.
        
        Параметры:
            run_id: идентификатор запуска (для Telegraph и имён файлов)
            raw_findings: данные от бэкенда/фронта (считаем корректными). 
                          Если None — используется MockBackend.
        
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
        if self.debug:
            print("\n" + "═" * 70 + f"\n🚀 ЗАПУСК WORKFLOW (run_id: {run_id})\n" + "═" * 70)

        # ============================================
        # ШАГ 1: Получаем данные (реальные или заглушку)
        # ============================================
        if raw_findings is None:
            # Демо-режим: используем заглушки из mocks.py
            if IS_MOCK:
                all_findings = MockBackend.get_all_findings()
                if self.debug:
                    print(f"\n▶️ [BACKEND] Использую заглушку MockBackend. Находок: {len(all_findings)}")
            else:
                logger.error("❌ Реальные данные не переданы, а IS_MOCK=False. Нечем работать!")
                return None
        else:
            # Продакшн: данные от бэкенда/фронта считаем корректными
            all_findings = raw_findings
            if self.debug:
                print(f"\n▶️ [BACKEND] Получены данные. Находок: {len(all_findings)}")

        if self.debug:
            print(f"Передаю в AI-анализатор...")

        # ============================================
        # ШАГ 2: AI-анализ (3 отчёта: summary, text, json)
        # ============================================
        reports = await self.analyzer.analyze_and_return(all_findings)
        summary, text_report, json_report = reports["summary"], reports["text"], reports["json"]

        # ============================================
        # ШАГ 3: Публикуем полный отчёт в Telegraph
        # ============================================
        report_url = None
        try:
            report_url = await self.telegraph.publish_report(
                run_id, text_report, summary, len(all_findings)
            )
            if self.debug:
                print(f"\n🌐 Отчёт опубликован в Telegraph: {report_url}")
        except Exception as e:
            logger.error(f"❌ Ошибка публикации в Telegraph: {e}")
            report_url = None

        # ============================================
        # ШАГ 4: Сохраняем JSON на диск (для интеграции в дашборды)
        # ============================================
        json_file = f"report_{run_id}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(json_report, f, ensure_ascii=False, indent=2)
        if self.debug:
            print(f"\n💾 JSON отчёт сохранён в {json_file} (для интеграции)")

        # ============================================
        # ШАГ 5: Эмуляция фронта (ТОЛЬКО в debug-режиме!)
        # ============================================
        if self.debug:
            MockFrontend.on_final_result(text_report, json_report, len(all_findings))

        # ============================================
        # ШАГ 6: Отправка через выбранный канал
        # ============================================
        if self.channel == "telegram":
            await self._send_to_telegram(run_id, summary, report_url, len(all_findings))
        elif self.channel == "email":
            await self._send_to_email(run_id, summary, report_url, len(all_findings))
        else:
            logger.warning(f"⚠️ Неизвестный канал: {self.channel}. Доступны: telegram, email")

        if self.debug:
            print("\n" + "═" * 70 + "\n✅ WORKFLOW ЗАВЕРШЁН\n" + "═" * 70 + "\n")

        # ============================================
        # ШАГ 7: Возвращаем результат (для бэкендера)
        # ============================================
        return {
            "run_id": run_id,
            "summary": summary,
            "text_report": text_report,
            "json_report": json_report,
            "report_url": report_url,
            "findings_count": len(all_findings)
        }

    async def _send_to_telegram(self, run_id: str, summary: str, report_url: str, count: int):
        """Отправка в Telegram: короткий summary + ссылка на полный отчёт."""
        if not self.recipient:
            if self.debug:
                print("\n⚠️ Получатель не указан — пропускаем.")
            return
        chat_id = resolve_recipient(self.recipient, self.storage)
        if not chat_id:
            if self.debug:
                print(f"\n⚠️ Пользователь '{self.recipient}' не найден. Напиши боту /start.")
            return
        if not self.tg_bot:
            if self.debug:
                print("\n⚠️ Telegram-бот не настроен — пропускаем.")
            return

        # Экранируем HTML-символы в summary
        summary_escaped = (
            summary
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

        # Формируем сообщение с кликабельной ссылкой
        message = f"{summary_escaped}\n\n"
        if report_url:
            message += f'📄 <a href="{report_url}">Полный отчёт</a>\n'
        message += f"🤖 Провайдер AI: {self.analyzer.provider}"

        await self.tg_bot.send_message(chat_id, message, parse_mode="HTML")
        if self.debug:
            print(f"\n📨 Краткий отчёт + ссылка отправлены в Telegram (chat_id={chat_id})")

    async def _send_to_email(self, run_id: str, summary: str, report_url: str, count: int):
        """Отправка на email: короткий summary + ссылка на полный отчёт (БЕЗ JSON-вложения)."""
        if not self.recipient:
            if self.debug:
                print("\n⚠️ Email получателя не указан — пропускаем.")
            return
        if not self.email_notifier.is_configured():
            if self.debug:
                print("\n⚠️ SMTP не настроен в .env — пропускаем.")
            return

        subject = f"🔍 Cyber Garden — Отчёт (run_id: {run_id}, {count} находок)"

        # Формируем тело письма: summary + ссылка
        body = f"{summary}\n\n"
        body += "━" * 40 + "\n\n"
        if report_url:
            body += f"📄 Полный отчёт: {report_url}\n\n"
        body += "━" * 40 + "\n\n"
        body += f"🤖 Провайдер AI: {self.analyzer.provider}\n"
        body += f"📋 Всего находок: {count}\n"
        body += f"🆔 Run ID: {run_id}\n\n"
        body += "💾 JSON-отчёт для интеграции сохранён локально (запроси у администратора)."

        # Отправляем БЕЗ вложения JSON-файла
        success = self.email_notifier.send(
            recipient=self.recipient,
            subject=subject,
            text_body=body
        )
        if success:
            if self.debug:
                print(f"\n📧 Отчёт отправлен на email: {self.recipient}")
        else:
            if self.debug:
                print(f"\n❌ Не удалось отправить email на {self.recipient}")