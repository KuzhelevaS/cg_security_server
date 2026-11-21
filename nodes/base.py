# nodes/base.py
from abc import ABC, abstractmethod
from pathlib import Path
from dataclasses import dataclass
from typing import Any

@dataclass
class NodeContext:
    """Контекст, который передается в каждую ноду при запуске."""
    files: list[Path]       # Все доступные файлы проекта
    root: Path              # Корень репозитория (для относительных путей)
    run_id: str             # ID запуска
    # Здесь в будущем появятся настройки ноды, выбранные пользователем
    
@dataclass
class Finding:
    """Единый формат результата для всех проверок (соответствует ТЗ)."""
    rule_id: str
    name: str
    severity: str           # CRITICAL, HIGH, MEDIUM, LOW
    file: str               # Относительный путь
    line: int
    snippet: str            # Замаскированный кусок кода
    raw_data: str = ""      # Сырые данные для LLM

class BaseNode(ABC):
    """Абстрактный базовый класс для всех нод проверки."""
    
    @property
    @abstractmethod
    def node_type(self) -> str:
        """Уникальный идентификатор ноды (например, 'secrets_scanner')."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Человекочитаемое имя для интерфейса."""
        pass

    @abstractmethod
    def run(self, context: NodeContext) -> list[Finding]:
        """
        Основной метод, который выполняет проверку.
        Должен быть реализован в каждой дочерней ноде.
        """
        pass 