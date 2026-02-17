from __future__ import annotations

from abc import ABC, abstractmethod


class PasswordVerifierAbstract(ABC):
    """Checks if candidate password matches a target hash representation."""

    @abstractmethod
    def verify(self, password_bytes: bytes, target_hash: str) -> bool:  # pragma: no cover
        raise NotImplementedError

    @property
    @abstractmethod
    def algorithm_name(self) -> str:  # pragma: no cover
        raise NotImplementedError
