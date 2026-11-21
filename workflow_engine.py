# workflow_engine.py
import asyncio
from pathlib import Path
from typing import AsyncIterator

from workflow_session import WorkflowSession
from nodes.base import NodeContext
from nodes.secrets import SecretsNode
from nodes.sca import ScaNode
from nodes.sast import SastNode


class WorkflowEngine:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    def _build_tree(self, nodes_data: list[dict]) -> dict:
        tree = {n["id"]: {"node": n, "children": []} for n in nodes_data}
        for n in nodes_data:
            for parent_id in n.get("parentid", []):
                if parent_id == -1:
                    continue
                if parent_id in tree:
                    tree[parent_id]["children"].append(n["id"])
        return tree

    def _make_node(self, scanner_type: str):
        if scanner_type == "secrets":
            return SecretsNode()
        if scanner_type == "sca":
            return ScaNode(db_path=self.db_path)
        if scanner_type == "sast":
            return SastNode()
        return None

    async def execute_graph(
        self,
        graph_json: list[dict],
        context: NodeContext,
        session: WorkflowSession,
    ) -> AsyncIterator[dict]:
        tree = self._build_tree(graph_json)
        roots = [n["id"] for n in graph_json if -1 in n.get("parentid", [])]

        message_config = None
        llm_config = None
        queue = list(roots)
        visited: set = set()

        while queue:
            current_id = queue.pop(0)
            if current_id in visited:
                continue
            visited.add(current_id)

            node_data = tree[current_id]["node"]
            node_type = node_data.get("type")
            info = node_data.get("info", {})

            session.current_text = f"Выполняется: {node_type} ({info.get('type', '')})"
            yield {"type": "node_start", "node_id": current_id, "node_type": node_type}

            try:
                if node_type == "message":
                    message_config = info
                    session.data_ready = True
                    yield {
                        "type": "node_result",
                        "node_id": current_id,
                        "findings": [],
                    }

                elif node_type == "llmtype":
                    llm_config = info
                    yield {
                        "type": "node_result",
                        "node_id": current_id,
                        "findings": [],
                    }

                elif node_type in ("trigger_button", "trigger_schedule", "projecttype"):
                    # Триггеры и источник — просто контекст
                    yield {
                        "type": "node_result",
                        "node_id": current_id,
                        "findings": [],
                    }

                elif node_type == "check":
                    scanner_type = info.get("type")
                    node_instance = self._make_node(scanner_type)
                    if node_instance is None:
                        session.status = "error"
                        session.error_text = f"Неизвестный тип проверки: {scanner_type}"
                        yield {
                            "type": "node_error",
                            "node_id": current_id,
                            "message": session.error_text,
                        }
                        return

                    findings = await asyncio.to_thread(node_instance.run, context)
                    if findings:
                        session.findings.extend([f.__dict__ for f in findings])
                    yield {
                        "type": "node_result",
                        "node_id": current_id,
                        "findings": [f.__dict__ for f in (findings or [])],
                    }

                else:
                    # Неизвестный тип — пропускаем, но не валим весь прогон
                    yield {
                        "type": "node_result",
                        "node_id": current_id,
                        "findings": [],
                    }

            except Exception as e:
                session.status = "error"
                session.error_text = f"Ошибка в ноде {node_type} ({info.get('type','')}): {e}"
                yield {
                    "type": "node_error",
                    "node_id": current_id,
                    "message": session.error_text,
                }
                return

            # Добавляем детей в очередь
            for child_id in tree[current_id]["children"]:
                queue.append(child_id)

        # Сортировка по критичности (CRITICAL -> LOW)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        session.findings.sort(
            key=lambda x: severity_order.get(x.get("severity", "LOW"), 5)
        )

        # Формируем итоговый JSON по ТЗ
        session.final_data = {
            "message_config": message_config,
            "llm_config": llm_config,
            "findings": session.findings,
        }
        session.status = "ended"
        session.current_text = "Анализ завершен"
        session.data_ready = True

        yield {
            "type": "workflow_done",
            "findings_count": len(session.findings),
        }