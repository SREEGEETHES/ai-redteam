import pytest

from app.adapters.agent import AgentAdapter
from app.adapters.base import OllamaAdapter, OpenAICompatibleAdapter, RESTAdapter
from app.adapters.rag import RAGAdapter
from app.adapters.registry import AdapterRegistry


class TestRESTAdapter:
    def test_adapter_creation(self):
        adapter = RESTAdapter("http://localhost:8000", {"timeout": 10})
        assert adapter.base_url == "http://localhost:8000"
        assert adapter.timeout == 10

    def test_adapter_creation_with_headers(self):
        adapter = RESTAdapter(
            "http://localhost:8000", {"headers": {"Authorization": "Bearer token"}}
        )
        assert "Authorization" in adapter.headers


class TestOllamaAdapter:
    def test_adapter_creation(self):
        adapter = OllamaAdapter("http://localhost:11434", {"timeout": 30})
        assert adapter.base_url == "http://localhost:11434"


class TestOpenAICompatibleAdapter:
    def test_adapter_creation(self):
        adapter = OpenAICompatibleAdapter("http://localhost:8000", {"timeout": 30})
        assert adapter.base_url == "http://localhost:8000"


class TestRAGAdapter:
    def test_adapter_creation(self):
        adapter = RAGAdapter("http://localhost:8000", {"tenant_id": "tenant-a"})
        assert adapter.base_url == "http://localhost:8000"
        assert adapter._tenant_id == "tenant-a"

    def test_canary_secret_defined(self):
        adapter = RAGAdapter("http://localhost:8000")
        assert adapter._canary_secret == "CANARY_SECRET_12345"


class TestAgentAdapter:
    def test_adapter_creation(self):
        adapter = AgentAdapter("http://localhost:8000", {"sandbox": "strict"})
        assert adapter.base_url == "http://localhost:8000"
        assert adapter._sandbox == "strict"


class TestAdapterRegistry:
    def test_get_supported_types(self):
        types = AdapterRegistry.get_supported_types()
        assert "rest" in types
        assert "ollama" in types
        assert "openai_compatible" in types
        assert "rag" in types
        assert "agent" in types

    def test_create_rest_adapter(self):
        adapter = AdapterRegistry.create_adapter("rest", "http://localhost:8000")
        assert isinstance(adapter, RESTAdapter)

    def test_create_ollama_adapter(self):
        adapter = AdapterRegistry.create_adapter("ollama", "http://localhost:11434")
        assert isinstance(adapter, OllamaAdapter)

    def test_create_openai_adapter(self):
        adapter = AdapterRegistry.create_adapter("openai_compatible", "http://localhost:8000")
        assert isinstance(adapter, OpenAICompatibleAdapter)

    def test_create_rag_adapter(self):
        adapter = AdapterRegistry.create_adapter("rag", "http://localhost:8000")
        assert isinstance(adapter, RAGAdapter)

    def test_create_agent_adapter(self):
        adapter = AdapterRegistry.create_adapter("agent", "http://localhost:8000")
        assert isinstance(adapter, AgentAdapter)

    def test_unknown_adapter_raises(self):
        with pytest.raises(ValueError):
            AdapterRegistry.create_adapter("unknown", "http://localhost:8000")
