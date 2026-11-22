"""
Движок выполнения графа workflow.
Обходит ноды в топологическом порядке, запускает сканеры,
собирает findings и обновляет WorkflowSession.
НЕ является async-генератором — просто await-функция.
"""
import asyncio
from pathlib import Path
from typing import Any

from workflow_session import WorkflowSession
from nodes.base import NodeContext
from nodes.secrets import SecretsNode
from nodes.sca import ScaNode
from nodes.sast import SastNode


class WorkflowEngine:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    def _build_tree(self, nodes_data: list[dict]) -> dict:
        """Строим дерево: id -> {node, children}."""
        tree = {}
        for n in nodes_data:
            tree[n["id"]] = {"node": n, "children": []}
        for n in nodes_data:
            for parent_id in n.get("parentid", []):
                if parent_id == -1:
                    continue
                if parent_id in tree:
                    tree[parent_id]["children"].append(n["id"])
        return tree

    async def execute_graph(
        self,
        graph_json: list[dict],
        context: NodeContext,
        session: WorkflowSession,
    ):
        """
        Выполняет граф workflow. НЕ является генератором.
        Напрямую обновляет session (current_text, final_data, status).
        """
        tree = self._build_tree(graph_json)
        roots = [n["id"] for n in graph_json if -1 in n.get("parentid", [])]

        message_config = None
        llm_config = None
        all_findings: list[dict] = []

        queue = list(roots)

        while queue:
            current_id = queue.pop(0)
            node_data = tree[current_id]["node"]
            node_type = node_data.get("type")
            info = node_data.get("info", {})

            # Обновляем статус в сессии — фронт увидит это через polling
            session.current_text = f"Выполняется: {node_type} ({info.get('type', '')})"

            # 1. Обработка сообщений и LLM
            if node_type == "message":
                message_config = info
                session.data_ready = True  # Данные готовы к отправке

            elif node_type == "llmtype":
                llm_config = info

            # 2. Обработка триггеров и источников
            elif node_type in ("trigger_button", "trigger_schedule", "projecttype"):
                pass  # Просто задают контекст, ничего не делают

            # 3. Обработка проверок (сканеров)
            elif node_type == "check":
                scanner_type = info.get("type")
                node_instance = None

                # Фабрика нод
                if scanner_type == "secrets":
                    node_instance = SecretsNode()
                elif scanner_type == "sca":
                    node_instance = ScaNode(db_path=self.db_path)
                elif scanner_type == "sast":
                    node_instance = SastNode()

                if node_instance:
                    try:
                        # Запускаем в потоке, чтобы не блокировать event loop
                        result = await asyncio.to_thread(node_instance.run, context)
                        if result:
                            # Finding — dataclass с 4 полями (type, line, file, severity)
                            # __dict__ превращает его в словарь для JSON-сериализации
                            all_findings.extend([f.__dict__ for f in result])
                    except Exception as e:
                        session.status = "error"
                        session.error_text = f"Ошибка в ноде {scanner_type}: {e}"
                        return
                else:
                    session.status = "error"
                    session.error_text = f"Неизвестный тип проверки: {scanner_type}"
                    return

            # 4. Обработка логических нод (if/else) — пока пропускаем
            elif node_type == "logic":
                pass

            # Добавляем детей в очередь
            for child_id in tree[current_id]["children"]:
                queue.append(child_id)

        # Сортировка по критичности (CRITICAL -> LOW)
        severity_order = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
        }
        all_findings.sort(
            key=lambda x: severity_order.get(x.get("severity", "LOW"), 5)
        )

        # Формируем итоговый JSON по ТЗ
        session.final_data = {
            "message_config": message_config,
            "llm_config": llm_config,
            "findings": all_findings,
        }
        session.status = "ended"
        session.current_text = "Анализ завершен"