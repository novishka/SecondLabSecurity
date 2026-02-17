from __future__ import annotations

from app.domain.interfaces.password_verifier import PasswordVerifierAbstract


def get_verifier_cls(algo: str) -> type[PasswordVerifierAbstract]:
    key = algo.strip().lower()
    if key == "md5":
        from app.infrastructure.hashing.md5_verifier import Md5PasswordVerifier

        return Md5PasswordVerifier
    if key in {"sha1", "sha-1"}:
        from app.infrastructure.hashing.sha1_verifier import Sha1PasswordVerifier

        return Sha1PasswordVerifier
    if key == "bcrypt":
        from app.infrastructure.hashing.bcrypt_verifier import BcryptPasswordVerifier

        return BcryptPasswordVerifier
    if key in {"argon2", "argon2id"}:
        from app.infrastructure.hashing.argon2_verifier import Argon2idPasswordVerifier

        return Argon2idPasswordVerifier

    raise ValueError(f"Unsupported algorithm: {algo}") from None
