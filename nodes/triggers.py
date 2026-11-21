# nodes/triggers.py
from .workflow import WorkflowNode, NodeConfig
from .base import NodeContext, Finding
from typing import Any

class ButtonTrigger(WorkflowNode):
    """Триггер ручного запуска (по кнопке)."""
    @property
    def node_type(self) -> str: return "trigger_button"

    @property
    def display_name(self) -> str: return "Ручной запуск"

    def run(self, context: NodeContext) -> list[Finding]:
        # Триггер просто пропускает контекст дальше
        return [] 

class ScheduleTrigger(WorkflowNode):
    """Триггер запуска по расписанию."""
    @property
    def node_type(self) -> str: return "trigger_schedule"

    @property
    def display_name(self) -> str: 
        cron = self.params.get("cron", "0 0 * * *")
        return f"По расписанию ({cron})"

    def run(self, context: NodeContext) -> list[Finding]:
        return []