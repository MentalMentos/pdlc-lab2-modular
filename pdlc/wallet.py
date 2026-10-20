"""Класс Wallet: имя, пара ключей, учебный адрес."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property

from pdlc.crypto import KeyPair, sha256_hex


@dataclass(frozen=True)
class Wallet:
    name: str
    keypair: KeyPair

    @classmethod
    def new(cls, name: str) -> "Wallet":
        return cls(name=name, keypair=KeyPair.generate())

    @cached_property
    def address(self) -> str:
        """SHA-256 от сырого открытого ключа (64 lower-case HEX)."""
        return sha256_hex(self.keypair.public_bytes)

    @property
    def public_hex(self) -> str:
        return self.keypair.public_hex

    def __repr__(self) -> str:  # для логов
        return f"Wallet({self.name!r}, addr={self.address[:12]}…)"
