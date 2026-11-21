"""
╔══════════════════════════════════════════════════════════════════════════╗
║  ⚠️  ВНИМАНИЕ: ТЕСТОВЫЕ ДАННЫЕ (ЗАГЛУШКИ)                              ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  Этот файл содержит ЗАГЛУШКИ для тестирования AI-модуля                  ║
║  БЕЗ реального бэкенда и фронтенда.                                      ║
║                                                                          ║
║  📦 MockBackend  — эмулирует бэкенд (сканеры), возвращает тестовые       ║
║                    находки (15 штук: 5 secrets + 5 sca + 5 logic).       ║
║                    В реальности эти данные придут от сканеров            ║
║                    (SecretsScanner, SCAScanner, SASTScanner).            ║
║                                                                          ║
║  📺 MockFrontend — эмулирует фронтенд, печатает отчёт в консоль.         ║
║                    В реальности фронт получает данные по WebSocket       ║
║                    и отображает их в UI.                                 ║
║                                                                          ║
║  🚩 ФЛАГ: IS_MOCK = True                                                 ║
║     Если этот флаг True — используются заглушки.                         ║
║     Если False — нужно передавать реальные данные от бэкенда.            ║
║                                                                          ║
║  🧪 ИНСТРУКЦИЯ ПО ПРОВЕРКЕ:                                              ║
║     1. Быстрый тест AI (без Telegram):                                   ║
║        python main_ai.py --quick                                         ║
║                                                                          ║
║     2. Полный пайплайн с отправкой в Telegram:                           ║
║        python main_ai.py --mock @username                                ║
║                                                                          ║
║     3. Отправка на Email:                                                ║
║        python main_ai.py --mock-email user@example.com                   ║
║                                                                          ║
║     4. Список зарегистрированных пользователей:                          ║
║        python main_ai.py --list-users                                    ║
║                                                                          ║
║  📋 ТЕСТОВЫЕ ДАННЫЕ приближены к ground-truth учебного репозитория:      ║
║     - 5 secrets (пароли, API-ключи, токены)                              ║
║     - 5 sca (уязвимые библиотеки с CVE)                                  ║
║     - 5 logic (SQL-инъекции, TLS-обход, CORS, авторизация)               ║
║                                                                          ║
║  ❌ НЕ УДАЛЯТЬ ЭТОТ ФАЙЛ — он нужен для демо жюри!                       ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import json


# ============================================
# 🚩 ФЛАГ: ИСПОЛЬЗУЕМ ЛИ ЗАГЛУШКИ
# ============================================
# Если True — Orchestrator использует MockBackend, когда реальные данные не переданы.
# Если False — нужно всегда передавать реальные данные от бэкенда.
IS_MOCK = True


# ============================================
# 📦 MOCK BACKEND (эмуляция бэкенда)
# ============================================
class MockBackend:
    """
    Эмуляция бэкенда. Возвращает тестовые находки.
    В реальности эти данные придут от сканеров:
      - SecretsScanner (секреты в коде)
      - SCAScanner (уязвимые библиотеки)
      - SASTScanner (логические ошибки в коде)

    Формат данных соответствует тому, что отдаёт реальный бэкенд:
      {
          "1": {"priority": "HIGH", "type": "secrets", "locate": [...]},
          "2": {...}
      }
    """

    # Флаг, что это тестовые данные
    IS_MOCK = True

    @staticmethod
    def get_all_findings() -> dict:
        """
        Возвращает ВСЕ тестовые находки (15 штук).
        Используется в Orchestrator.run(), когда реальные данные не переданы.
        """
        return {
            # === SECRETS (5 находок) ===
            "1": {
                "priority": "HIGH",
                "type": "secrets",
                "locate": [{
                    "file": "src/main/kotlin/lab/repairdesk/integration/PartsImportSettings.kt",
                    "line": 4,
                    "code": 'private val dbPassword = "P@ssw0rd!"'
                }]
            },
            "2": {
                "priority": "MEDIUM",
                "type": "secrets",
                "locate": [{
                    "file": "src/main/kotlin/lab/repairdesk/integration/QuoteRequest.kt",
                    "line": 7,
                    "code": 'header("X-Api-Key", "sk-1234567890")'
                }]
            },
            "3": {
                "priority": "HIGH",
                "type": "secrets",
                "locate": [{
                    "file": "src/main/resources/application.yml",
                    "line": 13,
                    "code": "  token: eyJhbGciOiJIUzI1NiJ9..."
                }]
            },
            "4": {
                "priority": "LOW",
                "type": "secrets",
                "locate": [{
                    "file": "src/main/kotlin/lab/repairdesk/integration/DepotStatusClient.kt",
                    "line": 8,
                    "code": 'private val fallbackSecret = "default-secret"'
                }]
            },
            "5": {
                "priority": "MEDIUM",
                "type": "secrets",
                "locate": [{
                    "file": "src/main/kotlin/lab/repairdesk/integration/WarrantyHeaders.kt",
                    "line": 7,
                    "code": 'header("Authorization", "Bearer " + token)'
                }]
            },

            # === SCA (5 находок) ===
            "6": {
                "priority": "CRITICAL",
                "type": "sca",
                "locate": [{
                    "file": "build.gradle.kts",
                    "line": 31,
                    "code": 'implementation("org.apache.commons:commons-text:1.9")'
                }],
                "advisoryIds": ["CVE-2022-42889", "GHSA-599f-7c49-w659"],
                "group": "org.apache.commons",
                "artifact": "commons-text",
                "version": "1.9"
            },
            "7": {
                "priority": "HIGH",
                "type": "sca",
                "locate": [{
                    "file": "build.gradle.kts",
                    "line": 32,
                    "code": 'implementation("org.jsoup:jsoup:1.14.1")'
                }],
                "advisoryIds": ["CVE-2021-37714"],
                "group": "org.jsoup",
                "artifact": "jsoup",
                "version": "1.14.1"
            },
            "8": {
                "priority": "MEDIUM",
                "type": "sca",
                "locate": [{
                    "file": "build.gradle.kts",
                    "line": 33,
                    "code": 'implementation("org.apache.commons:commons-compress:1.25.0")'
                }],
                "advisoryIds": ["CVE-2024-25710"],
                "group": "org.apache.commons",
                "artifact": "commons-compress",
                "version": "1.25.0"
            },
            "9": {
                "priority": "MEDIUM",
                "type": "sca",
                "locate": [{
                    "file": "build.gradle.kts",
                    "line": 36,
                    "code": 'add("implementation", "commons-net:commons-net:3.8.0")'
                }],
                "advisoryIds": ["CVE-2021-37533"],
                "group": "commons-net",
                "artifact": "commons-net",
                "version": "3.8.0"
            },
            "10": {
                "priority": "HIGH",
                "type": "sca",
                "locate": [{
                    "file": "build.gradle.kts",
                    "line": 38,
                    "code": 'implementation("org.json:json:20230227")'
                }],
                "advisoryIds": ["CVE-2023-5072"],
                "group": "org.json",
                "artifact": "json",
                "version": "20230227"
            },

            # === LOGIC (5 находок) ===
            "11": {
                "priority": "HIGH",
                "type": "logic",
                "locate": [{
                    "file": "src/main/kotlin/lab/repairdesk/repair/RepairLookupController.kt",
                    "line": 13,
                    "code": 'val sql = "SELECT * FROM repairs WHERE tag = " + frameTag'
                }]
            },
            "12": {
                "priority": "MEDIUM",
                "type": "logic",
                "locate": [{
                    "file": "src/main/kotlin/lab/repairdesk/integration/SupplierHttpsClient.kt",
                    "line": 13,
                    "code": 'conn.setHostnameVerifier { _, _ -> true }'
                }]
            },
            "13": {
                "priority": "MEDIUM",
                "type": "logic",
                "locate": [{
                    "file": "src/main/kotlin/lab/repairdesk/config/RepairCors.kt",
                    "line": 13,
                    "code": 'allowedOriginPatterns = listOf("*")'
                }]
            },
            "14": {
                "priority": "HIGH",
                "type": "logic",
                "locate": [{
                    "file": "src/main/kotlin/lab/repairdesk/config/RepairSecurity.kt",
                    "line": 18,
                    "code": '.requestMatchers(HttpMethod.GET, "/api/pickup/export").permitAll()'
                }]
            },
            "15": {
                "priority": "HIGH",
                "type": "logic",
                "locate": [{
                    "file": "src/main/kotlin/lab/repairdesk/repair/RepairTicketReader.kt",
                    "line": 10,
                    "code": 'fun read(ticketId: Long): Ticket? = repository.findById(ticketId)'
                }]
            },
        }

    @staticmethod
    def get_findings_by_category() -> dict[str, dict[str, dict]]:
        """
        Возвращает находки, сгруппированные по категориям.
        Удобно для теста по одной категории за раз.
        """
        all_findings = MockBackend.get_all_findings()
        grouped = {"secrets": {}, "sca": {}, "logic": {}}
        for fid, data in all_findings.items():
            ftype = data.get("type", "unknown")
            if ftype in grouped:
                grouped[ftype][fid] = data
        return grouped


# ============================================
# 📺 MOCK FRONTEND (эмуляция фронтенда)
# ============================================
class MockFrontend:
    """
    Эмуляция фронтенда. Печатает отчёт в консоль.
    В реальности фронт получает данные по WebSocket
    и отображает их в UI (React/Vue).

    Флаг IS_MOCK = True означает, что это заглушка.
    """

    # Флаг, что это тестовые данные
    IS_MOCK = True

    @staticmethod
    def on_final_result(text_report: str, json_report: dict, findings_count: int):
        """
        Эмуляция получения итогового отчёта фронтом.
        В реальности это WebSocket-сообщение от бэкенда.
        """
        print("\n" + "─" * 70)
        print(f"📡 [MOCK FRONTEND] Итоговый отчёт | находок: {findings_count}")
        print("─" * 70)
        print("ТЕКСТОВЫЙ ОТЧЁТ:")
        print(text_report)
        print("\nJSON ОТЧЁТ:")
        print(json.dumps(json_report, ensure_ascii=False, indent=2))
        print("─" * 70)

    @staticmethod
    def on_intermediate_result(node_id: str, category: str, report: str, findings_count: int):
        """
        Эмуляция промежуточного результата (по одной категории).
        В реальности это WebSocket-сообщение при завершении каждой ноды.
        """
        print("\n" + "─" * 70)
        print(f"📡 [MOCK FRONTEND] Нода: {node_id} | Категория: {category}")
        print(f"   Находок: {findings_count}")
        print("─" * 70)
        print(report)
        print("─" * 70)