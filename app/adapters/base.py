from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse
import httpx
import json

from app.core.config import settings
from app.core.logging import get_logger
from app.security.authorization import TargetAuthorizationGuard, AuthorizationError

logger = get_logger(__name__)
guard = TargetAuthorizationGuard()


class TargetAdapter(ABC):
    """Base class for all target adapters"""

    def __init__(self, base_url: str, config: Dict[str, Any] = None):
        self.base_url = base_url.rstrip("/")
        self.config = config or {}
        self.timeout = self.config.get("timeout", 30)
        self.headers = self.config.get("headers", {})
        self._client = httpx.Client(timeout=self.timeout, headers=self.headers)

    @abstractmethod
    def test_connection(self) -> bool:
        """Test if the target is reachable and responding"""

    @abstractmethod
    def get_baseline(self) -> Dict[str, Any]:
        """Get baseline response from the target"""

    @abstractmethod
    def send_attack(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send an attack payload and get response"""

    @abstractmethod
    def get_retrieved_documents(self) -> Optional[List[Dict[str, Any]]]:
        """Get retrieved documents (RAG-specific)"""

    @abstractmethod
    def get_tool_calls(self) -> Optional[List[Dict[str, Any]]]:
        """Get tool calls (Agent-specific)"""

    def close(self) -> None:
        self._client.close()


class RESTAdapter(TargetAdapter):
    """REST API target adapter"""

    def test_connection(self) -> bool:
        """Test connection to REST API"""
        try:
            response = self._client.get(f"{self.base_url}/health")
            response.raise_for_status()
            logger.info("rest_connection_ok", url=self.base_url)
            return True
        except Exception as e:
            logger.warning("rest_connection_failed", url=self.base_url, error=str(e))
            return False

    def get_baseline(self) -> Dict[str, Any]:
        """Get baseline response from REST API"""
        try:
            response = self._client.post(f"{self.base_url}/chat", json={"message": "hello"})
            response.raise_for_status()
            data = response.json()
            return {
                "status_code": response.status_code,
                "response": data,
                "headers": dict(response.headers),
            }
        except Exception as e:
            logger.error("rest_baseline_failed", error=str(e))
            return {"status_code": 0, "response": {}, "headers": {}}

    def send_attack(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send attack payload to REST API"""
        try:
            response = self._client.post(f"{self.base_url}/chat", json=payload)
            response.raise_for_status()
            data = response.json()
            return {
                "status_code": response.status_code,
                "response": data,
                "headers": dict(response.headers),
            }
        except Exception as e:
            logger.error("rest_attack_failed", error=str(e))
            return {"status_code": 0, "response": {}, "headers": {}}

    def get_retrieved_documents(self) -> Optional[List[Dict[str, Any]]]:
        """REST adapters don't have retrieved documents"""
        return None

    def get_tool_calls(self) -> Optional[List[Dict[str, Any]]]:
        """REST adapters don't have tool calls"""
        return None


class OllamaAdapter(TargetAdapter):
    """Ollama model adapter"""

    def test_connection(self) -> bool:
        """Test connection to Ollama"""
        try:
            response = self._client.get(f"{self.base_url}/api/tags")
            response.raise_for_status()
            logger.info("ollama_connection_ok", url=self.base_url)
            return True
        except Exception as e:
            logger.warning("ollama_connection_failed", url=self.base_url, error=str(e))
            return False

    def get_baseline(self) -> Dict[str, Any]:
        """Get baseline response from Ollama"""
        try:
            response = self._client.post(
                f"{self.base_url}/api/chat",
                json={"model": "llama2", "messages": [{"role": "user", "content": "hello"}]},
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            return {
                "status_code": response.status_code,
                "response": data,
                "headers": dict(response.headers),
            }
        except Exception as e:
            logger.error("ollama_baseline_failed", error=str(e))
            return {"status_code": 0, "response": {}, "headers": {}}

    def send_attack(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send attack payload to Ollama"""
        try:
            response = self._client.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            return {
                "status_code": response.status_code,
                "response": data,
                "headers": dict(response.headers),
            }
        except Exception as e:
            logger.error("ollama_attack_failed", error=str(e))
            return {"status_code": 0, "response": {}, "headers": {}}

    def get_retrieved_documents(self) -> Optional[List[Dict[str, Any]]]:
        """Ollama adapters don't expose retrieved documents"""
        return None

    def get_tool_calls(self) -> Optional[List[Dict[str, Any]]]:
        """Ollama adapters don't have tool calls"""
        return None


class OpenAICompatibleAdapter(TargetAdapter):
    """OpenAI-compatible API adapter"""

    def test_connection(self) -> bool:
        """Test connection to OpenAI-compatible API"""
        try:
            response = self._client.get(f"{self.base_url}/v1/models")
            response.raise_for_status()
            logger.info("openai_connection_ok", url=self.base_url)
            return True
        except Exception as e:
            logger.warning("openai_connection_failed", url=self.base_url, error=str(e))
            return False

    def get_baseline(self) -> Dict[str, Any]:
        """Get baseline response from OpenAI-compatible API"""
        try:
            response = self._client.post(
                f"{self.base_url}/v1/chat/completions",
                json={
                    "model": "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": "hello"}],
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            return {
                "status_code": response.status_code,
                "response": data,
                "headers": dict(response.headers),
            }
        except Exception as e:
            logger.error("openai_baseline_failed", error=str(e))
            return {"status_code": 0, "response": {}, "headers": {}}

    def send_attack(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send attack payload to OpenAI-compatible API"""
        try:
            response = self._client.post(
                f"{self.base_url}/v1/chat/completions",
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            return {
                "status_code": response.status_code,
                "response": data,
                "headers": dict(response.headers),
            }
        except Exception as e:
            logger.error("openai_attack_failed", error=str(e))
            return {"status_code": 0, "response": {}, "headers": {}}

    def get_retrieved_documents(self) -> Optional[List[Dict[str, Any]]]:
        """OpenAI adapters don't expose retrieved documents"""
        return None

    def get_tool_calls(self) -> Optional[List[Dict[str, Any]]]:
        """OpenAI adapters don't have tool calls"""
        return None