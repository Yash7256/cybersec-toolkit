import time
from abc import ABC, abstractmethod
from typing import Dict, Any, List

class ScannerRunner(ABC):
    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    async def scan(self, target_ip: str, ports: List[int]) -> Dict[str, Any]:
        """
        Scan the target IP for the specified ports.
        Returns a dictionary:
        {
            "results": {"80": "open", "443": "closed"},
            "scan_time": 1.23,
            "error": None
        }
        """
        pass
