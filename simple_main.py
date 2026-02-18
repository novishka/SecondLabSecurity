"""Простая программа для подбора пароля."""
import sys
import time
from simple_hashing import get_verifier
from simple_bruteforce import bruteforce


# Наборы символов
CHARSETS = {
    "digits": "0123456789",
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alnum": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "special": "!@#$%^&*()-_+=[]{}|;:',.<>?/~`",
}

# Тестовые хэши
TEST_CASES = {
    "sha1": [
        ("easy", "7c4a8d09ca3762af61e59520943dc26494f8941b", "digits", 1, 8),
        ("medium", "d0be2dc421be4fcd0172e5afceea3970e2f3d940", "lower", 1, 8),
        ("hard", "666846867fc5e0a46a7afc53eb8060967862f333", "alnum", 1, 8),
        ("very_hard", "6e157c5da4410b7e9de85f5c93026b9176e69064", "alnum", 1, 10),
    ],
    "md5": [
        ("easy", "e10adc3949ba59abbe56e057f20f883e", "digits", 1, 8),
        ("medium", "1f3870be274f6c49b3e31a0c6728957f", "lower", 1, 8),
        ("hard", "77892341aa9dc66e97f5c248782b5d92", "alnum", 1, 8),
        ("very_hard", "686e697538050e4664636337cc3b834f", "alnum", 1, 10),
    ],
    "bcrypt": [
        ("easy", "$2a$10$z4u9ZkvopUiiytaNX7wfGedy9Lu2ywUxwYpbsAR5YBrAuUs3YGXdi", "digits", 1, 8),
        ("medium", "$2a$10$26GB/T2/6aTsMkTjCgqm/.JP8SUjr32Bhfn9m9smtDiIwM4QIt2ze", "lower", 1, 8),
        ("hard", "$2a$10$Q9M0vLLrE4/nu/9JEMXFTewB3Yr9uMdIEZ1Sgdk1NQTjHwLN0asfi", "alnum", 1, 8),
        ("very_hard", "$2a$10$yZBadi8Szw0nItV2g96P6eqctI2kbG/.mb0uD/ID9tlof0zpJLLL2", "alnum", 1, 10),
    ],
    "argon2": [
        ("easy", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$PUF5UxxoUY++mMekkQwFurL0ZsTtB7lelO23zcyZQ0c", "digits", 1, 8),
        ("medium", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$HYQwRUw9VcfkvqkUQ5ppyYPom6f/ro3ZCXYznhrYZw4", "lower", 1, 8),
        ("hard", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$9asGA7Xv3vQBz7Yyh4/Ntw0GQgOg8R6OWolOfRETrEg", "alnum", 1, 8),
        ("very_hard", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$+smq45/czydGj0lYNdZVXF++FOXJwrkXt6VUIcEauvo", "alnum", 1, 10),
    ],
}


def main():
    if len(sys.argv) < 2:
        print("Использование:")
        print("  python simple_main.py <algo> [<hash>] [--workers N] [--timeout S]")
        print("\nАлгоритмы: sha1, md5, bcrypt, argon2")
        print("\nПримеры:")
        print("  python simple_main.py test sha1")
        print("  python simple_main.py sha1 7c4a8d09ca3762af61e59520943dc26494f8941b")
        print("  python simple_main.py md5 e10adc3949ba59abbe56e057f20f883e --workers 8")
        print("  python simple_main.py md5 HASH --workers 8 --timeout 60")
        return

    cmd = sys.argv[1].lower()

    # Тестовый режим
    if cmd == "test":
        if len(sys.argv) > 2:
            algo = sys.argv[2].lower()
            test_cases = TEST_CASES.get(algo, [])
        else:
            # Тестируем всё
            for algo in TEST_CASES:
                test_cases = TEST_CASES[algo]
                print(f"\n{'=' * 60}")
                print(f"Тестирование {algo.upper()}")
                print('=' * 60)
                _run_tests(algo, test_cases)
            return

        if not test_cases:
            print(f"Неизвестный алгоритм: {algo}")
            return

        print(f"\nТестирование {algo.upper()}")
        print('=' * 60)
        _run_tests(algo, test_cases)
        return

    #直接крек
    algo = cmd
    if len(sys.argv) < 3:
        print("Укажите хэш")
        return

    target_hash = sys.argv[2]

    # Парсим опции
    workers = 1
    timeout = None
    charset_name = "alnum"
    min_len = 1
    max_len = 8

    for i in range(3, len(sys.argv)):
        if sys.argv[i] == "--workers" and i + 1 < len(sys.argv):
            workers = int(sys.argv[i + 1])
        elif sys.argv[i] == "--timeout" and i + 1 < len(sys.argv):
            timeout = float(sys.argv[i + 1])
        elif sys.argv[i] == "--charset" and i + 1 < len(sys.argv):
            charset_name = sys.argv[i + 1]
        elif sys.argv[i] == "--min-len" and i + 1 < len(sys.argv):
            min_len = int(sys.argv[i + 1])
        elif sys.argv[i] == "--max-len" and i + 1 < len(sys.argv):
            max_len = int(sys.argv[i + 1])

    charset = CHARSETS.get(charset_name, CHARSETS["alnum"])

    _crack_hash(algo, target_hash, charset, min_len, max_len, workers, timeout)


def _run_tests(algo: str, test_cases: list):
    """Запустить тесты для алгоритма."""
    try:
        verifier = get_verifier(algo)
    except ValueError as e:
        print(f"Ошибка: {e}")
        return

    for label, target_hash, charset_name, min_len, max_len in test_cases:
        charset = CHARSETS[charset_name]
        print(f"\n{label.upper()}:")
        print(f"  Hash: {target_hash[:40]}...")
        print(f"  Charset: {charset_name}, Length: {min_len}-{max_len}")
        print("  Cracking...", end="", flush=True)

        start = time.perf_counter()
        result = bruteforce(
            target_hash,
            verifier,
            charset=charset,
            min_len=min_len,
            max_len=max_len,
            workers=1,
            timeout=60,
        )
        elapsed = time.perf_counter() - start

        if result["found"]:
            print(f"\n  ✓ НАЙДЕН: '{result['password']}'")
            print(f"    Попыток: {result['attempts']:,}")
            print(f"    Время: {result['time']:.2f}s")
        else:
            print(f"\n  ✗ НЕ НАЙДЕН за {elapsed:.2f}s")
            print(f"    Попыток: {result['attempts']:,}")


def _crack_hash(algo: str, target_hash: str, charset: str, min_len: int, max_len: int, workers: int, timeout: float):
    """Одиночный крек хэша."""
    print(f"\nПодбор {algo.upper()} хэша...")
    print(f"Hash: {target_hash[:60]}...")
    print(f"Charset: {len(charset)} символов, Max length: {max_len}")
    print(f"Workers: {workers}, Timeout: {timeout or 'none'}s")
    print("-" * 60)

    try:
        verifier = get_verifier(algo)
    except ValueError as e:
        print(f"Ошибка: {e}")
        return

    print("Searching...", end="", flush=True)
    start = time.perf_counter()

    result = bruteforce(
        target_hash,
        verifier,
        charset=charset,
        min_len=min_len,
        max_len=max_len,
        workers=workers,
        timeout=timeout,
    )

    elapsed = time.perf_counter() - start

    print()
    if result["found"]:
        print(f"Found: '{result['password']}'")
        print(f"  Attempts: {result['attempts']:,}")
        print(f"  Time: {result['time']:.2f}s")
        attempts_per_sec = result['attempts'] / result['time'] if result['time'] > 0 else 0
        print(f"  Speed: {attempts_per_sec:,.0f} attempts/sec")
    else:
        print(f"Not found in {elapsed:.2f}s")
        print(f"  Attempts: {result['attempts']:,}")
        attempts_per_sec = result['attempts'] / elapsed if elapsed > 0 else 0
        print(f"  Speed: {attempts_per_sec:,.0f} attempts/sec")


if __name__ == "__main__":
    main()
