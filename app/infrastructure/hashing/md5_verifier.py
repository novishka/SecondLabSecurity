from __future__ import annotations

import hashlib

from app.domain.interfaces.password_verifier import PasswordVerifierAbstract


class Md5PasswordVerifier(PasswordVerifierAbstract):
    @property
    def algorithm_name(self) -> str:
        return "md5"

    def verify(self, password_bytes: bytes, target_hash: str) -> bool:
        # target_hash is expected to be hex MD5 digest
        try:
            target_digest = bytes.fromhex(target_hash.strip())
        except ValueError:
            raise ValueError("Invalid MD5 hex digest") from None
        return hashlib.md5(password_bytes).digest() == target_digest
