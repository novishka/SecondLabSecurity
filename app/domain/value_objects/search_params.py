from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SearchParams:
    charset: str
    min_len: int
    max_len: int
    encoding: str = "utf-8"

    def validate(self) -> None:
        if not self.charset:
            raise ValueError("charset must be non-empty")
        if self.min_len <= 0 or self.max_len <= 0:
            raise ValueError("min_len/max_len must be > 0")
        if self.min_len > self.max_len:
            raise ValueError("min_len must be <= max_len")
