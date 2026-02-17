from __future__ import annotations

import hashlib

from app.domain.interfaces.password_verifier import PasswordVerifierAbstract


class Sha1PasswordVerifier(PasswordVerifierAbstract):
    @property
    def algorithm_name(self) -> str:
        return "sha1"

    def verify(self, password_bytes: bytes, target_hash: str) -> bool:
        # target_hash is expected to be hex SHA-1 digest
        try:
            target_digest = bytes.fromhex(target_hash.strip())
        except ValueError:
            raise ValueError("Invalid SHA-1 hex digest") from None
        return hashlib.sha1(password_bytes).digest() == target_digest
