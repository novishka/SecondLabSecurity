from __future__ import annotations


def index_to_bytes(index: int, charset_bytes: bytes, length: int) -> bytes:
    """Convert integer index to fixed-length password over charset (base-N)."""
    base = len(charset_bytes)
    if base <= 0:
        raise ValueError("charset must be non-empty")
    if length <= 0:
        raise ValueError("length must be > 0")

    out = bytearray(length)
    i = index
    for pos in range(length - 1, -1, -1):
        i, rem = divmod(i, base)
        out[pos] = charset_bytes[rem]
    return bytes(out)


def iter_range_passwords(charset_bytes: bytes, length: int, start: int, end: int) -> tuple[int, bytes]:
    """
    Yield (attempt_index, password_bytes) for indices in [start, end).
    attempt_index is the absolute index in this length-space.
    """
    for idx in range(start, end):
        yield idx, index_to_bytes(idx, charset_bytes, length)
