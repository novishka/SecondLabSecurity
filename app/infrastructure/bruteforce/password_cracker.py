from __future__ import annotations

import math
import time
from dataclasses import dataclass
from multiprocessing import Event, Queue, Value, get_context
from queue import Empty

from app.domain.entities.crack_result import CrackResult
from app.domain.interfaces.password_verifier import PasswordVerifierAbstract
from app.domain.value_objects.search_params import SearchParams
from app.infrastructure.bruteforce.indexed_generator import iter_range_passwords


@dataclass(frozen=True, slots=True)
class _WorkItem:
    length: int
    start: int
    end: int


def _worker(
    verifier_cls: type[PasswordVerifierAbstract],
    target_hash: str,
    charset_bytes: bytes,
    encoding: str,
    work_items: list[_WorkItem],
    found_event: Event,
    result_queue: Queue,
    attempts_counter: Value,
    started: float,
    time_limit_seconds: float | None,
    max_attempts: int | None,
) -> None:
    verifier = verifier_cls()
    local_attempts = 0
    flush_every = 2048

    verify = verifier.verify
    for item in work_items:
        if found_event.is_set():
            break
        for _, pw_bytes in iter_range_passwords(charset_bytes, item.length, item.start, item.end):
            if found_event.is_set():
                break
            local_attempts += 1

            if local_attempts % flush_every == 0:
                with attempts_counter.get_lock():
                    attempts_counter.value += local_attempts
                    total_attempts = int(attempts_counter.value)
                local_attempts = 0
                if max_attempts is not None and total_attempts >= max_attempts:
                    found_event.set()
                    break

            if time_limit_seconds is not None and (time.perf_counter() - started) >= time_limit_seconds:
                found_event.set()
                break

            if verify(pw_bytes, target_hash):
                try:
                    pw_str = pw_bytes.decode(encoding)
                except UnicodeDecodeError:
                    pw_str = pw_bytes.decode(encoding, errors="replace")
                if local_attempts:
                    with attempts_counter.get_lock():
                        attempts_counter.value += local_attempts
                    local_attempts = 0
                found_event.set()
                result_queue.put(("found", pw_str))
                return

    if local_attempts:
        with attempts_counter.get_lock():
            attempts_counter.value += local_attempts
        local_attempts = 0
    result_queue.put(("done", None))


class PasswordCracker:
    def __init__(self, verifier_cls: type[PasswordVerifierAbstract]) -> None:
        self._verifier_cls = verifier_cls

    def crack(
        self,
        *,
        target_hash: str,
        search: SearchParams,
        workers: int = 1,
        time_limit_seconds: float | None = None,
        max_attempts: int | None = None,
    ) -> CrackResult:
        """
        Bruteforce search for a password matching target_hash.

        - workers=1 uses a single process.
        - workers>1 uses multiprocessing (spawn-safe for Windows).
        """
        charset = search.charset
        encoding = search.encoding
        min_len = search.min_len
        max_len = search.max_len

        charset_bytes = charset.encode(encoding, errors="strict")
        if len(set(charset_bytes)) != len(charset_bytes):
            # Ensure deterministic space and prevent redundant work.
            charset_bytes = bytes(dict.fromkeys(charset_bytes).keys())

        started = time.perf_counter()

        if workers <= 1:
            verifier = self._verifier_cls()
            found, pw, attempts = self._crack_single(
                verifier=verifier,
                target_hash=target_hash,
                charset_bytes=charset_bytes,
                encoding=encoding,
                min_len=min_len,
                max_len=max_len,
                time_limit_seconds=time_limit_seconds,
                max_attempts=max_attempts,
            )
            seconds = time.perf_counter() - started
            return CrackResult(found=found, password=pw, attempts=attempts, seconds=seconds)

        ctx = get_context("spawn")
        found_event = ctx.Event()
        result_queue: Queue = ctx.Queue()
        attempts_counter: Value = ctx.Value("Q", 0)

        # Prepare chunked work items (contiguous index ranges).
        work_by_length = []
        for length in range(min_len, max_len + 1):
            total = len(charset_bytes) ** length
            work_by_length.append((length, total))

        # Distribute work roughly evenly across workers.
        all_items: list[_WorkItem] = []
        for length, total in work_by_length:
            if total <= 0:
                continue
            # chunk size: about 64 chunks per worker per length (heuristic)
            chunks = max(workers * 64, workers)
            chunk_size = max(1, math.ceil(total / chunks))
            for start in range(0, total, chunk_size):
                end = min(total, start + chunk_size)
                all_items.append(_WorkItem(length=length, start=start, end=end))

        # Round-robin assign items to workers.
        per_worker: list[list[_WorkItem]] = [[] for _ in range(workers)]
        for idx, item in enumerate(all_items):
            per_worker[idx % workers].append(item)

        procs = [
            ctx.Process(
                target=_worker,
                args=(
                    self._verifier_cls,
                    target_hash,
                    charset_bytes,
                    encoding,
                    per_worker[i],
                    found_event,
                    result_queue,
                    attempts_counter,
                    started,
                    time_limit_seconds,
                    max_attempts,
                ),
                daemon=True,
            )
            for i in range(workers)
        ]

        for p in procs:
            p.start()

        found_password: str | None = None
        try:
            done = 0
            while done < workers and any(p.is_alive() for p in procs):
                try:
                    status, payload = result_queue.get(timeout=0.1)
                except Empty:
                    status, payload = None, None
                if status == "found" and found_password is None:
                    found_password = str(payload)
                    found_event.set()
                    break
                if status == "done":
                    done += 1
        finally:
            found_event.set()
            for p in procs:
                if p.is_alive():
                    p.terminate()
            for p in procs:
                p.join(timeout=2.0)

        seconds = time.perf_counter() - started
        attempts_total = int(attempts_counter.value)
        return CrackResult(
            found=found_password is not None,
            password=found_password,
            attempts=attempts_total,
            seconds=seconds,
        )

    def _crack_single(
        self,
        *,
        verifier: PasswordVerifierAbstract,
        target_hash: str,
        charset_bytes: bytes,
        encoding: str,
        min_len: int,
        max_len: int,
        time_limit_seconds: float | None,
        max_attempts: int | None,
    ) -> tuple[bool, str | None, int]:
        started = time.perf_counter()
        attempts = 0
        verify = verifier.verify

        for length in range(min_len, max_len + 1):
            total = len(charset_bytes) ** length
            for idx, pw_bytes in iter_range_passwords(charset_bytes, length, 0, total):
                _ = idx
                attempts += 1
                if max_attempts is not None and attempts > max_attempts:
                    return False, None, attempts
                if time_limit_seconds is not None and (time.perf_counter() - started) >= time_limit_seconds:
                    return False, None, attempts
                if verify(pw_bytes, target_hash):
                    try:
                        return True, pw_bytes.decode(encoding), attempts
                    except UnicodeDecodeError:
                        return True, pw_bytes.decode(encoding, errors="replace"), attempts

        return False, None, attempts
