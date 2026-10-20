"""Транзакция: создание, сериализация, проверка.

Поля body (ровно 5): sender, recipient, amount, nonce, public_key.
Полная транзакция = body + {tx_id, signature}.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Set

from pdlc.crypto import (
    KeyPair, canonical_json, sha256_hex, verify,
)
from pdlc.wallet import Wallet


class TxValidationError(ValueError):
    """Исключение валидации транзакции."""


# ─── структура подписанной транзакции ──────────────────────────────────
@dataclass(frozen=True)
class SignedTransaction:
    sender: str
    recipient: str
    amount: int
    nonce: int
    public_key: str
    tx_id: str
    signature: str

    def to_dict(self) -> dict:
        return {
            "sender":     self.sender,
            "recipient":  self.recipient,
            "amount":     self.amount,
            "nonce":      self.nonce,
            "public_key": self.public_key,
            "tx_id":      self.tx_id,
            "signature":  self.signature,
        }

    @classmethod
    def from_dict(cls, d: Mapping) -> "SignedTransaction":
        return cls(
            sender     = d["sender"],
            recipient  = d["recipient"],
            amount     = d["amount"],
            nonce      = d["nonce"],
            public_key = d["public_key"],
            tx_id      = d["tx_id"],
            signature  = d["signature"],
        )


# ─── конструктор транзакции ────────────────────────────────────────────
class TxBuilder:
    """Собирает подписанную транзакцию из тела и подписывает её."""

    @staticmethod
    def _validate_body(amount, nonce) -> None:
        if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
            raise TxValidationError("amount должен быть положительным int")
        if isinstance(nonce, bool) or not isinstance(nonce, int) or nonce < 0:
            raise TxValidationError("nonce должен быть неотрицательным int")

    @classmethod
    def build(cls, sender: Wallet, recipient_address: str,
              amount: int, nonce: int) -> SignedTransaction:
        cls._validate_body(amount, nonce)
        if sender.address == recipient_address:
            raise TxValidationError("sender совпадает с recipient")
        body = {
            "sender":     sender.address,
            "recipient":  recipient_address,
            "amount":     amount,
            "nonce":      nonce,
            "public_key": sender.public_hex,
        }
        message   = canonical_json(body)
        tx_id     = sha256_hex(message)
        signature = sender.keypair.sign(message).hex()
        return SignedTransaction(
            tx_id=tx_id, signature=signature, **body,
        )


# ─── проверяющий ───────────────────────────────────────────────────────
class TxVerifier:
    """Проверяет подписанную транзакцию (без изменения состояния)."""

    REQUIRED = {"sender", "recipient", "amount", "nonce", "public_key",
                "tx_id", "signature"}

    def __init__(self, known_addresses: Set[str]) -> None:
        self.known = frozenset(known_addresses)

    def verify(self, raw: Mapping,
               balances: Mapping[str, int],
               next_nonce: Mapping[str, int]) -> tuple[bool, str]:
        """Возвращает (ok, reason)."""
        if set(raw.keys()) != self.REQUIRED:
            return False, "неверный набор полей транзакции"

        try:
            tx = SignedTransaction.from_dict(raw)
        except KeyError as exc:
            return False, f"отсутствует поле {exc.args[0]}"

        # формат полей
        if not (isinstance(tx.sender, str) and len(tx.sender) == 64):
            return False, "sender не 64 hex"
        if not (isinstance(tx.recipient, str) and len(tx.recipient) == 64):
            return False, "recipient не 64 hex"
        if isinstance(tx.amount, bool) or not isinstance(tx.amount, int) \
                or tx.amount <= 0:
            return False, "amount должно быть положительным целым"
        if isinstance(tx.nonce, bool) or not isinstance(tx.nonce, int) \
                or tx.nonce < 0:
            return False, "nonce должно быть неотрицательным целым"
        if not (isinstance(tx.public_key, str) and len(tx.public_key) == 64):
            return False, "public_key не 64 hex"
        if not (isinstance(tx.tx_id, str) and len(tx.tx_id) == 64):
            return False, "tx_id не 64 hex"
        if not (isinstance(tx.signature, str) and len(tx.signature) == 128):
            return False, "signature не 128 hex"

        if tx.sender == tx.recipient:
            return False, "sender совпадает с recipient"
        if tx.sender not in self.known or tx.recipient not in self.known:
            return False, "неизвестный адрес"

        # соответствие sender ↔ public_key
        try:
            pub_bytes = bytes.fromhex(tx.public_key)
        except ValueError:
            return False, "public_key: ошибка HEX"
        if sha256_hex(pub_bytes) != tx.sender:
            return False, "sender не соответствует public_key"

        # пересчёт tx_id
        body = {
            "sender":     tx.sender,
            "recipient":  tx.recipient,
            "amount":     tx.amount,
            "nonce":      tx.nonce,
            "public_key": tx.public_key,
        }
        message = canonical_json(body)
        if sha256_hex(message) != tx.tx_id:
            return False, "tx_id не соответствует body"

        # Ed25519-подпись
        if not verify(tx.public_key, message, tx.signature):
            return False, "неверная электронная подпись"

        # nonce
        expected = next_nonce.get(tx.sender, 0)
        if tx.nonce != expected:
            return False, f"неверный nonce (ожидался {expected}, пришёл {tx.nonce})"

        # баланс
        if balances.get(tx.sender, 0) < tx.amount:
            return (False,
                    f"недостаточно средств: баланс "
                    f"{balances.get(tx.sender, 0)}, требуется {tx.amount}")

        return True, "OK"
