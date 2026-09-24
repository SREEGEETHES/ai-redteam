from typing import Any

from .agent import AgentAdapter
from .base import OllamaAdapter, OpenAICompatibleAdapter, RESTAdapter
from .rag import RAGAdapter


class AdapterRegistry:
    """Registry for target adapters"""

    _adapters: dict[str, type] = {
        "rest": RESTAdapter,
        "ollama": OllamaAdapter,
        "openai_compatible": OpenAICompatibleAdapter,
        "rag": RAGAdapter,
        "agent": AgentAdapter,
    }

    @classmethod
    def get_adapter_class(cls, adapter_type: str) -> type:
        """Get adapter class by type"""
        adapter_class = cls._adapters.get(adapter_type)
        if not adapter_class:
            raise ValueError(f"Unknown adapter type: {adapter_type}")
        return adapter_class

    @classmethod
    def get_supported_types(cls) -> list[str]:
        """Get list of supported adapter types"""
        return list(cls._adapters.keys())

    @classmethod
    def create_adapter(
        cls,
        adapter_type: str,
        base_url: str,
        config: dict[str, Any] | None = None,
    ):
        """Create an adapter instance"""
        adapter_class = cls.get_adapter_class(adapter_type)
        return adapter_class(base_url=base_url, config=config)
