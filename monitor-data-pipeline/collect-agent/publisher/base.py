from abc import ABC, abstractmethod
from typing import List
from models import MetricBatch


class Publisher(ABC):
    @abstractmethod
    async def publish(self, batches: List[MetricBatch]):
        pass

    @abstractmethod
    async def close(self):
        pass
