"""Набор тестов для всех компонентов проекта."""
import time
import sys
import os
import json
import csv
from simple_hashing import (
    verify_sha1, verify_md5, verify_bcrypt, verify_argon2,
    get_verifier
)
from simple_bruteforce import bruteforce

# Вывод в папку out
output_dir = "out"
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

output_file_txt = os.path.join(output_dir, "out.txt")
output_file_csv = os.path.join(output_dir, "results.csv")
output_file_json = os.path.join(output_dir, "results.json")

# Глобальный список результатов тестов
test_results = []


def log_print(*args, **kwargs):
    """Вывод в консоль и в файл."""
    with open(output_file_txt, "a", encoding="utf-8") as f:
        print(*args, **kwargs)
        print(*args, **kwargs, file=f)


def test_hashing_functions():
    """Тестировать функции хэширования."""
    global test_results
    
    log_print("\n" + "="*70)
    log_print("TEST 1: Hash Functions")
    log_print("="*70)

    # SHA-1 тест
    assert verify_sha1("123456", "7c4a8d09ca3762af61e59520943dc26494f8941b")
    log_print("OK: SHA-1 verification works")

    # MD5 тест
    assert verify_md5("123456", "e10adc3949ba59abbe56e057f20f883e")
    log_print("OK: MD5 verification works")

    # bcrypt тест
    assert verify_bcrypt("123456", "$2a$10$z4u9ZkvopUiiytaNX7wfGedy9Lu2ywUxwYpbsAR5YBrAuUs3YGXdi")
    log_print("OK: bcrypt verification works")

    # argon2 тест
    assert verify_argon2("123456", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$PUF5UxxoUY++mMekkQwFurL0ZsTtB7lelO23zcyZQ0c")
    log_print("OK: Argon2 verification works")
    
    test_results.append({
        "test": "test_hashing_functions",
        "status": "PASSED",
        "details": "All hash functions verified successfully"
    })


def test_get_verifier():
    """Тестировать функцию get_verifier."""
    global test_results
    
    log_print("\n" + "="*70)
    log_print("TEST 2: Function get_verifier")
    log_print("="*70)

    verifiers = [
        ("sha1", "7c4a8d09ca3762af61e59520943dc26494f8941b"),
        ("md5", "e10adc3949ba59abbe56e057f20f883e"),
        ("bcrypt", "$2a$10$z4u9ZkvopUiiytaNX7wfGedy9Lu2ywUxwYpbsAR5YBrAuUs3YGXdi"),
        ("argon2", "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$PUF5UxxoUY++mMekkQwFurL0ZsTtB7lelO23zcyZQ0c"),
    ]

    for algo, target_hash in verifiers:
        verifier = get_verifier(algo)
        assert verifier("123456", target_hash), f"Failed for {algo}"
        log_print(f"OK: get_verifier('{algo}') works")

    # Тест на ошибку
    try:
        get_verifier("unknown_algo")
        assert False, "Should raise error"
    except ValueError:
        log_print("OK: get_verifier raises error for unknown algorithm")
    
    test_results.append({
        "test": "test_get_verifier",
        "status": "PASSED",
        "details": "All verifiers working correctly"
    })


def test_bruteforce_sha1():
    """Тестировать bruteforce для SHA-1."""
    global test_results
    
    log_print("\n" + "="*70)
    log_print("TEST 3: Bruteforce SHA-1")
    log_print("="*70)

    verifier = get_verifier("sha1")
    target_hash = "7c4a8d09ca3762af61e59520943dc26494f8941b"  # 123456
    charset = "0123456789"

    start = time.perf_counter()
    result = bruteforce(target_hash, verifier, charset, min_len=1, max_len=8, workers=1)
    elapsed = time.perf_counter() - start

    assert result["found"], "Should find password"
    assert result["password"] == "123456", f"Wrong password: {result['password']}"
    log_print(f"OK: Found password: '{result['password']}'")
    log_print(f"   Attempts: {result['attempts']:,}")
    log_print(f"   Time: {result['time']:.3f}s")
    log_print(f"   Speed: {result['attempts']/result['time']:,.0f} attempts/sec")
    
    test_results.append({
        "test": "test_bruteforce_sha1",
        "status": "PASSED",
        "details": f"Found password: {result['password']}",
        "attempts": result['attempts'],
        "time_sec": round(result['time'], 3),
        "speed_per_sec": int(result['attempts']/result['time']) if result['time'] > 0 else 0
    })


def test_bruteforce_md5():
    """Тестировать bruteforce для MD5."""
    global test_results
    
    log_print("\n" + "="*70)
    log_print("TEST 4: Bruteforce MD5")
    log_print("="*70)

    verifier = get_verifier("md5")
    target_hash = "e10adc3949ba59abbe56e057f20f883e"  # 123456
    charset = "0123456789"

    start = time.perf_counter()
    result = bruteforce(target_hash, verifier, charset, min_len=1, max_len=8, workers=1)
    elapsed = time.perf_counter() - start

    assert result["found"], "Should find password"
    assert result["password"] == "123456", f"Wrong password: {result['password']}"
    log_print(f"OK: Found password: '{result['password']}'")
    log_print(f"   Attempts: {result['attempts']:,}")
    log_print(f"   Time: {result['time']:.3f}s")
    log_print(f"   Speed: {result['attempts']/result['time']:,.0f} attempts/sec")
    
    test_results.append({
        "test": "test_bruteforce_md5",
        "status": "PASSED",
        "details": f"Found password: {result['password']}",
        "attempts": result['attempts'],
        "time_sec": round(result['time'], 3),
        "speed_per_sec": int(result['attempts']/result['time']) if result['time'] > 0 else 0
    })


def test_bruteforce_timeout():
    """Тестировать timeout функциональность."""
    global test_results
    
    log_print("\n" + "="*70)
    log_print("TEST 5: Timeout functionality")
    log_print("="*70)

    verifier = get_verifier("sha1")
    target_hash = "666846867fc5e0a46a7afc53eb8060967862f333"  # unknown
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    start = time.perf_counter()
    result = bruteforce(target_hash, verifier, charset, min_len=1, max_len=8, workers=1, timeout=0.5)
    elapsed = time.perf_counter() - start

    assert not result["found"], "Should not find password"
    assert result.get("timeout"), "Should have timeout flag"
    log_print(f"OK: Timeout works correctly")
    log_print(f"   Timeout set to: 0.5s")
    log_print(f"   Actual time: {elapsed:.3f}s")
    log_print(f"   Attempts before timeout: {result['attempts']:,}")
    
    test_results.append({
        "test": "test_bruteforce_timeout",
        "status": "PASSED",
        "details": "Timeout triggered correctly",
        "attempts": result['attempts'],
        "time_sec": round(elapsed, 3)
    })


def test_performance_comparison():
    """Сравнить производительность SHA-1 и MD5."""
    global test_results
    
    log_print("\n" + "="*70)
    log_print("TEST 6: Performance comparison SHA-1 vs MD5")
    log_print("="*70)

    # SHA-1 fast  find (123456)
    sha1_verifier = get_verifier("sha1")
    sha1_hash = "7c4a8d09ca3762af61e59520943dc26494f8941b"
    
    md5_verifier = get_verifier("md5")
    md5_hash = "e10adc3949ba59abbe56e057f20f883e"
    
    charset = "0123456789"

    # SHA-1
    start = time.perf_counter()
    sha1_result = bruteforce(sha1_hash, sha1_verifier, charset, min_len=1, max_len=8, workers=1)
    sha1_time = time.perf_counter() - start

    # MD5
    start = time.perf_counter()
    md5_result = bruteforce(md5_hash, md5_verifier, charset, min_len=1, max_len=8, workers=1)
    md5_time = time.perf_counter() - start

    sha1_speed = sha1_result['attempts'] / sha1_time
    md5_speed = md5_result['attempts'] / md5_time

    log_print(f"SHA-1 speed: {sha1_speed:,.0f} attempts/sec")
    log_print(f"MD5 speed:   {md5_speed:,.0f} attempts/sec")
    log_print(f"Ratio: SHA-1 is {sha1_speed/md5_speed:.2f}x {'faster' if sha1_speed > md5_speed else 'slower'}")
    
    test_results.append({
        "test": "test_performance_comparison",
        "status": "PASSED",
        "details": f"SHA-1 {sha1_speed:,.0f} vs MD5 {md5_speed:,.0f}",
        "sha1_speed": int(sha1_speed),
        "md5_speed": int(md5_speed),
        "ratio": round(sha1_speed/md5_speed, 2)
    })


def run_all_tests():
    """Запустить все тесты."""
    global test_results
    test_results = []
    
    # Очистить файлы вывода
    with open(output_file_txt, "w", encoding="utf-8") as f:
        f.write("")
    
    log_print("""
========================================================================
                         RUNNING ALL TESTS
========================================================================
""")

    tests = [
        test_hashing_functions,
        test_get_verifier,
        test_bruteforce_sha1,
        test_bruteforce_md5,
        test_bruteforce_timeout,
        test_performance_comparison,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            log_print(f"FAIL: Test failed: {e}")
            test_results.append({
                "test": test.__name__,
                "status": "FAILED",
                "error": str(e)
            })
            import traceback
            traceback.print_exc()

    log_print("\n" + "="*70)
    log_print(f"TEST RESULTS: {passed} passed, {failed} failed")
    log_print("="*70)

    if failed == 0:
        log_print("SUCCESS: ALL TESTS PASSED!")
    else:
        log_print(f"FAILED: {failed} TESTS FAILED")

    # Сохранить результаты в CSV и JSON
    _save_results_csv()
    _save_results_json()
    
    log_print(f"\nResults saved to:")
    log_print(f"  - {output_file_txt}")
    log_print(f"  - {output_file_csv}")
    log_print(f"  - {output_file_json}")

    if failed == 0:
        return 0
    else:
        return 1


def _save_results_csv():
    """Сохранить результаты в CSV."""
    with open(output_file_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "test", "status", "details", "attempts", "time_sec", "speed_per_sec", "error"
        ])
        writer.writeheader()
        for result in test_results:
            writer.writerow({
                "test": result.get("test", ""),
                "status": result.get("status", ""),
                "details": result.get("details", ""),
                "attempts": result.get("attempts", ""),
                "time_sec": result.get("time_sec", ""),
                "speed_per_sec": result.get("speed_per_sec", ""),
                "error": result.get("error", "")
            })


def _save_results_json():
    """Сохранить результаты в JSON."""
    with open(output_file_json, "w", encoding="utf-8") as f:
        json.dump(test_results, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    exit(run_all_tests())
