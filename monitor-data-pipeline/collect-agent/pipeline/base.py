from abc import ABC, abstractmethod
from models import MetricBatch, ProcessResult


class PipelineStage(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    async def process(self, batch: MetricBatch) -> ProcessResult:
        pass

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name})"
