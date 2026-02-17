from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CrackResult:
    found: bool
    password: str | None
    attempts: int
    seconds: float

    @property
    def rate_per_second(self) -> float:
        if self.seconds <= 0:
            return 0.0
        return self.attempts / self.seconds
