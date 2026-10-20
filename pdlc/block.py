"""Блок и его сборка/проверка."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Mapping, Set

from pdlc.crypto import canonical_json, sha256_hex
from pdlc.merkle import MerkleTree
from pdlc.tx import TxVerifier


@dataclass(frozen=True)
class Block:
    index: int
    prev_hash: str
    producer: str
    merkle_root: str
    transactions: List[dict]
    block_hash: str
    allocations: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "index":        self.index,
            "prev_hash":    self.prev_hash,
            "producer":     self.producer,
            "merkle_root":  self.merkle_root,
            "transactions": self.transactions,
            "block_hash":   self.block_hash,
        }
        if self.allocations:
            d["allocations"] = self.allocations
        return d


class BlockBuilder:
    """Собирает обычный блок или genesis."""

    @staticmethod
    def genesis(wallets, amount_each: int = 100) -> Block:
        allocations = sorted(
            [{"address": w.address, "amount": amount_each} for w in wallets],
            key=lambda a: a["address"],
        )
        header = {
            "index":       0,
            "prev_hash":   "00" * 32,
            "producer":    "GENESIS",
            "merkle_root": "00" * 32,
            "allocations": allocations,
        }
        return Block(
            index=0,
            prev_hash=header["prev_hash"],
            producer="GENESIS",
            merkle_root=header["merkle_root"],
            transactions=[],
            block_hash=sha256_hex(canonical_json(header)),
            allocations=allocations,
        )

    @staticmethod
    def build(index: int, prev_hash: str, producer: str,
              transactions: List[dict]) -> Block:
        tree = MerkleTree(transactions)
        header = {
            "index":       index,
            "prev_hash":   prev_hash,
            "producer":    producer,
            "merkle_root": tree.root,
        }
        return Block(
            index=index,
            prev_hash=prev_hash,
            producer=producer,
            merkle_root=tree.root,
            transactions=list(transactions),
            block_hash=sha256_hex(canonical_json(header)),
        )


class BlockVerifier:
    """Проверка блока на временной копии состояния."""

    def __init__(self, known_addresses: Set[str]) -> None:
        self.tx_verifier = TxVerifier(known_addresses)

    def verify(self, block: Block,
               last_block: Block,
               balances: Mapping[str, int],
               next_nonce: Mapping[str, int]) -> tuple[bool, str]:
        if block.index != last_block.index + 1:
            return (False,
                    f"неверный index: ожидался {last_block.index + 1}, "
                    f"пришёл {block.index}")
        if block.prev_hash != last_block.block_hash:
            return False, "prev_hash не совпадает с block_hash последнего блока"

        txs = block.transactions
        if not isinstance(txs, list) or not (1 <= len(txs) <= 3):
            return False, "размер списка транзакций не в [1, 3]"

        ids = [t.get("tx_id") for t in txs]
        if len(set(ids)) != len(ids):
            return False, "в блоке повторяются tx_id"

        if MerkleTree(txs).root != block.merkle_root:
            return False, "merkle_root не совпадает с пересчётом"

        header = {
            "index":       block.index,
            "prev_hash":   block.prev_hash,
            "producer":    block.producer,
            "merkle_root": block.merkle_root,
        }
        if sha256_hex(canonical_json(header)) != block.block_hash:
            return False, "block_hash не совпадает с пересчётом"

        tmp_bal   = dict(balances)
        tmp_nonce = dict(next_nonce)
        seen = set()
        for tx in txs:
            ok, reason = self.tx_verifier.verify(tx, tmp_bal, tmp_nonce)
            if not ok:
                return (False,
                        f"транзакция {tx.get('tx_id', '?')[:16]}…: {reason}")
            key = (tx["sender"], tx["nonce"])
            if key in seen:
                return False, "в блоке повтор пары (sender, nonce)"
            seen.add(key)
            tmp_bal[tx["sender"]]   -= tx["amount"]
            tmp_bal[tx["recipient"]] = tmp_bal.get(tx["recipient"], 0) \
                                      + tx["amount"]
            tmp_nonce[tx["sender"]] = tx["nonce"] + 1

        return True, "OK"
