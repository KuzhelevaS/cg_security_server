# nodes/workflow.py
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from .base import BaseNode, NodeContext, Finding

@dataclass
class NodeConfig:
    """Настройки, которые фронтенд присылает для конкретной ноды в графе."""
    id: str
    type: str
    params: dict = field(default_factory=dict)

class WorkflowNode(BaseNode):
    """Базовый класс для нод, которые используются в графе."""
    
    def __init__(self, config: NodeConfig):
        self.config = config
        self.params = config.params

    @property
    def node_type(self) -> str:
        return self.config.type

    @property
    def display_name(self) -> str:
        return f"{self.config.type} ({self.config.id})"