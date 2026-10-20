"""Дерево Меркла для подписанных транзакций."""

from __future__ import annotations

import logging
from typing import Iterable, List

from pdlc.crypto import canonical_json, sha256_bytes

log = logging.getLogger("pdlc.merkle")


class MerkleTree:
    """Строит дерево Меркла из набора транзакций.

    Листья  = SHA-256 от canonical(tx), включая tx_id и signature.
    Корень  = итерирование попарным H(a||b); при нечётном числе на уровне
              последний хэш дублируется ВНУТРИ вычисления.
    """

    EMPTY_ROOT = "00" * 32

    def __init__(self, transactions: Iterable[dict]) -> None:
        self._txs = list(transactions)
        self._levels: list[list[bytes]] = []
        self._root: str = self.EMPTY_ROOT
        self._build()

    @property
    def root(self) -> str:
        return self._root

    @property
    def levels(self) -> list[list[bytes]]:
        return self._levels

    def _build(self) -> None:
        if not self._txs:
            return
        leaves = [sha256_bytes(canonical_json(tx)) for tx in self._txs]
        self._levels.append(list(leaves))
        log.debug("merkle: level 0 (leaves): %d items", len(leaves))

        current = leaves
        depth = 0
        while len(current) > 1:
            if len(current) % 2 == 1:
                current = current + [current[-1]]  # дублируем внутри уровня
                log.debug("merkle: level %d is odd — duplicated last", depth)
            nxt = [
                sha256_bytes(current[i] + current[i + 1])
                for i in range(0, len(current), 2)
            ]
            depth += 1
            self._levels.append(list(nxt))
            log.debug("merkle: level %d: %d items", depth, len(nxt))
            current = nxt

        self._root = current[0].hex()

    def pretty_print(self) -> List[str]:
        """Возвращает строки для печати в лог/отчёт."""
        out = []
        for depth, level in enumerate(self._levels):
            label = "листья" if depth == 0 else f"уровень {depth}"
            out.append(f"  {label}:")
            for i, h in enumerate(level):
                prefix = "L" if depth == 0 else "N"
                out.append(f"    {prefix}{i} = {h.hex()}")
        out.append(f"  merkle_root = {self._root}")
        return out
