from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

class SecurityToolPlugin(ABC):
    """
    The master blueprint for all SentinelAI security tools.
    Every scanner must implement the abstract methods below.
    Optionally, tools may override construct_command() to support
    AI-driven argument generation via the schema in tools_registry.yaml.
    """

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """e.g., 'nmap', 'nuclei', 'subdomain'"""
        pass

    @abstractmethod
    def validate_roe(self, target: str) -> bool:
        """
        Checks if the target is within the Rules of Engagement.
        Must return False for localhost, internal IPs, or out-of-scope targets.
        """
        pass

    @abstractmethod
    def execute(self, target: str, args: Optional[Dict] = None) -> Any:
        """
        The actual subprocess call to the security tool.
        - target: the validated hostname/IP to scan
        - args: optional AI-generated parameters (validated against schema)
        """
        pass

    @abstractmethod
    def normalize(self, raw_results: Any) -> Dict:
        """Converts the tool's custom output into SentinelAI's standard JSON schema."""
        pass

    def construct_command(self, target: str, args: Optional[Dict] = None) -> str:
        """
        Optional override: builds the final CLI command from validated args.
        Default implementation returns a no-op string for tools without a schema.
        GenericBinaryPlugin overrides this with schema-driven validation.
        """
        raise NotImplementedError(f"{self.tool_name} does not support construct_command()")