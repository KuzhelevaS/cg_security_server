from abc import ABC, abstractmethod
from pathlib import Path
from dataclasses import dataclass

@dataclass
class NodeContext:
    """Контекст, который передается в каждую ноду при запуске."""
    files: list[Path]       # Все доступные файлы проекта
    root: Path              # Корень репозитория (для относительных путей)
    run_id: str             # ID запуска

@dataclass
class Finding:
    """Единый формат результата для всех проверок (строго 4 поля)."""
    type: str               # "SAST", "SECRET" или "SCA"
    line: int               # Номер строки
    file: str               # Относительный путь (сырой, обрезка будет в core.py)
    severity: str           # CRITICAL, HIGH, MEDIUM, LOW

class BaseNode(ABC):
    """Абстрактный базовый класс для всех нод проверки."""
    
    @property
    @abstractmethod
    def node_type(self) -> str:
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        pass

    @abstractmethod
    def run(self, context: NodeContext) -> list[Finding]:
        pass