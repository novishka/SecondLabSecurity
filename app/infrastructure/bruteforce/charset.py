from __future__ import annotations

import string


CHARSETS: dict[str, str] = {
    "digits": string.digits,
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "alpha": string.ascii_letters,
    "alnum": string.ascii_letters + string.digits,
    "hex": string.hexdigits.lower(),
    "printable": "".join(ch for ch in string.printable if ch not in "\r\n\t\x0b\x0c"),
}


def resolve_charset(name_or_value: str) -> str:
    key = name_or_value.strip()
    return CHARSETS.get(key, name_or_value)
