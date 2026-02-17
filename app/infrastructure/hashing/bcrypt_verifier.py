from __future__ import annotations

import bcrypt

from app.domain.interfaces.password_verifier import PasswordVerifierAbstract


class BcryptPasswordVerifier(PasswordVerifierAbstract):
    @property
    def algorithm_name(self) -> str:
        return "bcrypt"

    def verify(self, password_bytes: bytes, target_hash: str) -> bool:
        hashed = target_hash.strip().encode("utf-8")
        try:
            return bcrypt.checkpw(password_bytes, hashed)
        except ValueError:
            # invalid salt/hash format
            raise ValueError("Invalid bcrypt hash format") from None
