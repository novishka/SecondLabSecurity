from __future__ import annotations

from dataclasses import dataclass

from app.domain.entities.crack_result import CrackResult
from app.domain.value_objects.search_params import SearchParams
from app.infrastructure.bruteforce.password_cracker import PasswordCracker


@dataclass(frozen=True, slots=True)
class BenchmarkCommand:
    target_hash: str
    search: SearchParams
    length: int
    attempts: int
    workers: int = 1


class BenchmarkUseCase:
    def __init__(self, verifier_cls: type) -> None:
        self._cracker = PasswordCracker(verifier_cls=verifier_cls)

    def execute(self, command: BenchmarkCommand) -> CrackResult:
        command.search.validate()
        if command.length <= 0:
            raise ValueError("length must be > 0")
        if command.attempts <= 0:
            raise ValueError("attempts must be > 0")

        # Benchmark = "crack" but with hard max_attempts and fixed length.
        bench_search = SearchParams(
            charset=command.search.charset,
            min_len=command.length,
            max_len=command.length,
            encoding=command.search.encoding,
        )
        return self._cracker.crack(
            target_hash=command.target_hash,
            search=bench_search,
            workers=command.workers,
            time_limit_seconds=None,
            max_attempts=command.attempts,
        )
