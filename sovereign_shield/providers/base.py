"""
Abstract base class for LLM providers.

Any LLM can be used as a veto checker by implementing this interface.
"""

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """Base class for LLM verification providers."""

    @abstractmethod
    def verify(self, text: str) -> str:
        """
        Send user input to the LLM for attack classification.

        Args:
            text: The user input to classify.

        Returns:
            Raw LLM response string. VetoShield handles parsing/validation.
        """
        ...

    def verify_structured(self, text: str) -> str:
        """
        Send user input to the LLM and ask for a structured JSON verdict.

        Override this to take part in structured multi-model consensus. A
        provider that implements it should render
        `prompts.STRUCTURED_VERIFICATION_PROMPT` and return the model's raw
        reply; VetoShield does the parsing, schema validation, canonical
        normalization, and hashing.

        Providers that do NOT override this stay fully supported - VetoShield
        detects that and falls back to single-word verdict consensus for the
        whole panel, logging that the hash comparison is verdict-only.

        Returns:
            Raw LLM response string, expected to contain a JSON object with
            "verdict", "category" and "severity" keys.
        """
        raise NotImplementedError(
            f"{self.name} does not implement verify_structured()."
        )

    @classmethod
    def supports_structured(cls) -> bool:
        """True if this provider overrides verify_structured()."""
        return cls.verify_structured is not LLMProvider.verify_structured

    @property
    def name(self) -> str:
        return self.__class__.__name__
