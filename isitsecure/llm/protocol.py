"""Base protocol for LLM clients.

Defines the interface that all LLM client implementations must follow.
Uses Python's Protocol for structural subtyping (duck typing with type hints).
"""

from typing import Protocol, runtime_checkable


@runtime_checkable
class LLMClientProtocol(Protocol):
    """Protocol defining the interface for LLM clients.

    All LLM client implementations (Anthropic, Google, etc.) must implement
    these methods to be used interchangeably.

    This follows the Dependency Inversion Principle - high-level modules
    depend on this abstraction rather than concrete implementations.
    """

    @property
    def model_name(self) -> str:
        """Get the model name being used."""
        ...

    @property
    def llm(self):
        """Get the underlying LLM instance for advanced usage."""
        ...

    async def generate(
        self,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """Generate a response from the LLM.

        Args:
            prompt: The prompt to send
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature

        Returns:
            Generated text response
        """
        ...

    async def generate_with_system(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
    ) -> str:
        """Generate a response with a system prompt.

        Args:
            system_prompt: System instructions
            user_prompt: User's message
            max_tokens: Maximum tokens in response

        Returns:
            Generated text response
        """
        ...


@runtime_checkable
class VisionLLMClientProtocol(LLMClientProtocol, Protocol):
    """Extended protocol for LLM clients that support vision (image input)."""

    async def generate_with_image(
        self,
        prompt: str,
        image_base64: str,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> str:
        """Generate a response with an image input (vision).

        Args:
            prompt: The text prompt to send
            image_base64: Base64-encoded image data
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature

        Returns:
            Generated text response
        """
        ...
