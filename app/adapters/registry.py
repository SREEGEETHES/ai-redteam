from typing import Dict, Type, Optional, Any
from .base import RESTAdapter, OllamaAdapter, OpenAICompatibleAdapter
from .rag import RAGAdapter
from .agent import AgentAdapter


class AdapterRegistry:
    """Registry for target adapters"""

    _adapters: Dict[str, Type] = {
        "rest": RESTAdapter,
        "ollama": OllamaAdapter,
        "openai_compatible": OpenAICompatibleAdapter,
        "rag": RAGAdapter,
        "agent": AgentAdapter,
    }

    @classmethod
    def get_adapter_class(cls, adapter_type: str) -> Type:
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
        config: Optional[Dict[str, Any]] = None,
    ):
        """Create an adapter instance"""
        adapter_class = cls.get_adapter_class(adapter_type)
        return adapter_class(base_url=base_url, config=config)