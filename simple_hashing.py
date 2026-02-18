"""Простые функции для проверки паролей против хэшей."""
import hashlib
import bcrypt
from argon2 import PasswordHasher


def verify_sha1(password: str, target_hash: str) -> bool:
    """Проверить SHA-1 хэш."""
    computed = hashlib.sha1(password.encode()).hexdigest()
    return computed == target_hash.lower()


def verify_md5(password: str, target_hash: str) -> bool:
    """Проверить MD5 хэш."""
    computed = hashlib.md5(password.encode()).hexdigest()
    return computed == target_hash.lower()


def verify_bcrypt(password: str, target_hash: str) -> bool:
    """Проверить bcrypt хэш."""
    try:
        return bcrypt.checkpw(password.encode(), target_hash.encode())
    except Exception:
        return False


def verify_argon2(password: str, target_hash: str) -> bool:
    """Проверить Argon2 хэш."""
    try:
        hasher = PasswordHasher()
        hasher.verify(target_hash, password)
        return True
    except Exception:
        return False


def get_verifier(algo: str):
    """Получить функцию проверки для алгоритма."""
    algo = algo.lower().strip()
    if algo == "sha1" or algo == "sha-1":
        return verify_sha1
    elif algo == "md5":
        return verify_md5
    elif algo == "bcrypt":
        return verify_bcrypt
    elif algo == "argon2" or algo == "argon2id":
        return verify_argon2
    else:
        raise ValueError(f"Неизвестный алгоритм: {algo}")
