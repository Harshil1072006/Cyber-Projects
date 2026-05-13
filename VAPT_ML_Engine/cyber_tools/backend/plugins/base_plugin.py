"""
ToolPlugin base class.
Every tool integration must inherit from this class and implement:
  - build_command(): Returns a list of args (NEVER a string, prevents shell injection)
  - parse_output(): Parses raw stdout into a list of Finding dicts
"""
from abc import ABC, abstractmethod
from typing import Any

class ToolPlugin(ABC):
    name: str = "base"
    description: str = ""

    @abstractmethod
    def build_command(self, target: str, options: dict) -> list[str]:
        """
        Build the command as a list of strings.
        NEVER join into a shell string. NEVER use shell=True.
        Example: ["nmap", "-sV", "-T4", target]
        """
        pass

    @abstractmethod
    def parse_output(self, raw_output: str, target: str) -> list[dict[str, Any]]:
        """
        Parse raw stdout/stderr into a normalized list of Finding dicts.
        Each dict must have at minimum: type, title.
        """
        pass
