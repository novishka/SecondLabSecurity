from __future__ import annotations

from dataclasses import dataclass

from app.domain.entities.crack_result import CrackResult
from app.domain.value_objects.search_params import SearchParams
from app.infrastructure.bruteforce.password_cracker import PasswordCracker


@dataclass(frozen=True, slots=True)
class CrackHashCommand:
    target_hash: str
    search: SearchParams
    workers: int = 1
    time_limit_seconds: float | None = None
    max_attempts: int | None = None


class CrackHashUseCase:
    def __init__(self, verifier_cls: type) -> None:
        self._cracker = PasswordCracker(verifier_cls=verifier_cls)

    def execute(self, command: CrackHashCommand) -> CrackResult:
        command.search.validate()
        return self._cracker.crack(
            target_hash=command.target_hash,
            search=command.search,
            workers=command.workers,
            time_limit_seconds=command.time_limit_seconds,
            max_attempts=command.max_attempts,
        )
