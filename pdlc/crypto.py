"""Криптографические примитивы.

* Ed25519 — через библиотеку PyNaCl (nacl.signing), RFC 8032.
* SHA-256 — hashlib из стандартной библиотеки.
* Канонический JSON — compact, отсортированные ключи, ASCII.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


def canonical_json(obj: Any) -> bytes:
    """Унифицированная сериализация C(x) → UTF-8 байты.

    Все ключи объектов сортируются, компактные разделители,
    ensure_ascii=True (строки экранируются в \\uXXXX).
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class KeyPair:
    """Пара ключей Ed25519."""

    __slots__ = ("_sk", "_vk")

    def __init__(self, sk: SigningKey) -> None:
        self._sk = sk
        self._vk = sk.verify_key

    # ─── конструкторы ─────────────────────────────────────────────
    @classmethod
    def generate(cls) -> "KeyPair":
        return cls(SigningKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "KeyPair":
        if len(seed) != 32:
            raise ValueError("Ed25519 seed должен быть 32 байта")
        return cls(SigningKey(seed))

    # ─── свойства ────────────────────────────────────────────────
    @property
    def public_bytes(self) -> bytes:
        """Открытый ключ в raw-формате (32 байта)."""
        return bytes(self._vk)

    @property
    def public_hex(self) -> str:
        return self.public_bytes.hex()

    # ─── операции ────────────────────────────────────────────────
    def sign(self, message: bytes) -> bytes:
        """Возвращает чистую 64-байтовую подпись (без присоединения
        сообщения, как возвращает SigningKey.sign)."""
        return self._sk.sign(message).signature


def verify(public_hex: str, message: bytes, signature_hex: str) -> bool:
    """Пытается проверить подпись; возвращает только bool."""
    try:
        pub = bytes.fromhex(public_hex)
        sig = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if len(pub) != 32 or len(sig) != 64:
        return False
    try:
        VerifyKey(pub).verify(message, sig)
    except BadSignatureError:
        return False
    except Exception:
        return False
    return True
