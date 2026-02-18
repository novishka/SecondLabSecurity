"""Простой перебор паролей (brute force)."""
import time
from itertools import product
from multiprocessing import Process, Queue, Event
import os


def generate_passwords(charset: str, min_len: int, max_len: int):
    """Генерировать пароли по возрастающей длине."""
    for length in range(min_len, max_len + 1):
        for combo in product(charset, repeat=length):
            yield "".join(combo)


def _worker_process(
    charset: str,
    target_hashes: list,
    verifier,
    work_queue: Queue,
    result_queue: Queue,
    stop_event: Event,
):
    """Рабочий процесс для поиска пароля (оптимизирован для Intel Arc и многопроцессности)."""
    attempts = 0
    local_attempts = 0
    start_time = time.perf_counter()
    check_interval = 5000  # Проверяем stop_event реже для лучшей производительности

    while not stop_event.is_set():
        try:
            work = work_queue.get(timeout=0.1)
            if work is None:  # Сигнал выхода
                break

            min_len, max_len = work
            local_attempts = 0
            
            for password in generate_passwords(charset, min_len, max_len):
                if local_attempts % check_interval == 0 and stop_event.is_set():
                    break

                local_attempts += 1

                # Проверяем каждый хэш
                for target_hash in target_hashes:
                    if verifier(password, target_hash):
                        elapsed = time.perf_counter() - start_time
                        attempts += local_attempts
                        result_queue.put({
                            "found": True,
                            "password": password,
                            "hash": target_hash,
                            "attempts": attempts,
                            "time": elapsed,
                        })
                        stop_event.set()
                        return

                # Периодически отправляем прогресс
                if local_attempts % check_interval == 0:
                    attempts += local_attempts
                    result_queue.put({
                        "found": False,
                        "attempts": attempts,
                        "time": time.perf_counter() - start_time,
                    })
                    local_attempts = 0

        except Exception:
            pass

    elapsed = time.perf_counter() - start_time
    attempts += local_attempts
    result_queue.put({
        "found": False,
        "attempts": attempts,
        "time": elapsed,
        "done": True,
    })


def bruteforce_single(
    target_hash: str,
    verifier,
    charset: str,
    min_len: int = 1,
    max_len: int = 8,
    timeout: float = None,
):
    """Простой перебор без многопроцессности."""
    start_time = time.perf_counter()
    attempts = 0

    for password in generate_passwords(charset, min_len, max_len):
        attempts += 1

        if verifier(password, target_hash):
            elapsed = time.perf_counter() - start_time
            return {
                "found": True,
                "password": password,
                "attempts": attempts,
                "time": elapsed,
            }

        # Проверяем timeout
        if timeout and (time.perf_counter() - start_time) > timeout:
            elapsed = time.perf_counter() - start_time
            return {
                "found": False,
                "attempts": attempts,
                "time": elapsed,
                "timeout": True,
            }

    elapsed = time.perf_counter() - start_time
    return {
        "found": False,
        "attempts": attempts,
        "time": elapsed,
    }


def bruteforce_parallel(
    target_hash: str,
    verifier,
    charset: str,
    min_len: int = 1,
    max_len: int = 8,
    workers: int = 4,
    timeout: float = None,
):
    """Перебор с использованием нескольких процессов."""
    work_queue = Queue()
    result_queue = Queue()
    stop_event = Event()

    # Создаём рабочие процессы
    processes = []
    for _ in range(workers):
        p = Process(
            target=_worker_process,
            args=(charset, [target_hash], verifier, work_queue, result_queue, stop_event),
        )
        p.start()
        processes.append(p)

    # Генерируем задачи
    for length in range(min_len, max_len + 1):
        work_queue.put((length, length))

    # Отправляем сигналы выхода
    for _ in range(workers):
        work_queue.put(None)

    # Собираем результаты
    start_time = time.perf_counter()
    total_attempts = 0
    results = []

    while len([p for p in processes if p.is_alive()]) > 0 or not result_queue.empty():
        try:
            result = result_queue.get(timeout=0.5)
            results.append(result)

            if result.get("found"):
                stop_event.set()
                for p in processes:
                    if p.is_alive():
                        p.terminate()
                break

            total_attempts = result.get("attempts", total_attempts)

            if timeout and (time.perf_counter() - start_time) > timeout:
                stop_event.set()
                for p in processes:
                    if p.is_alive():
                        p.terminate()
                break

        except Exception:
            pass

    # Ждём завершения процессов
    for p in processes:
        if p.is_alive():
            p.terminate()
            p.join(timeout=1)

    elapsed = time.perf_counter() - start_time

    # Ищем результат "found"
    for result in results:
        if result.get("found"):
            return {
                "found": True,
                "password": result["password"],
                "attempts": total_attempts,
                "time": elapsed,
            }

    return {
        "found": False,
        "attempts": total_attempts,
        "time": elapsed,
    }


def bruteforce(
    target_hash: str,
    verifier,
    charset: str = "abcdefghijklmnopqrstuvwxyz",
    min_len: int = 1,
    max_len: int = 8,
    workers: int = 1,
    timeout: float = None,
):
    """Универсальная функция для перебора."""
    if workers == 1:
        return bruteforce_single(target_hash, verifier, charset, min_len, max_len, timeout)
    else:
        return bruteforce_parallel(
            target_hash, verifier, charset, min_len, max_len, workers, timeout
        )
