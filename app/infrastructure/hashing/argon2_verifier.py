from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

from app.domain.interfaces.password_verifier import PasswordVerifierAbstract


class Argon2idPasswordVerifier(PasswordVerifierAbstract):
    def __init__(self) -> None:
        self._ph = PasswordHasher()

    @property
    def algorithm_name(self) -> str:
        return "argon2id"

    def verify(self, password_bytes: bytes, target_hash: str) -> bool:
        # Argon2 PHC string already includes salt/params; we just verify.
        try:
            return self._ph.verify(target_hash.strip(), password_bytes.decode("utf-8"))
        except VerifyMismatchError:
            return False
        except (UnicodeDecodeError, VerificationError, ValueError):
            # treat decoding issues as mismatch for bruteforce
            return False
