"""Ledger: подтверждённое состояние реестра + mempool + chain."""

from __future__ import annotations

import copy
import logging
from typing import Dict, List

from pdlc.block import Block, BlockBuilder
from pdlc.tx import SignedTransaction, TxVerifier
from pdlc.wallet import Wallet

log = logging.getLogger("pdlc.state")


class Ledger:
    """Хранит chain, balances, next_nonce и очередь mempool."""

    def __init__(self, wallets: List[Wallet]) -> None:
        self._wallets = list(wallets)
        self.known_addresses = {w.address for w in wallets}
        self._addr_name = {w.address: w.name for w in wallets}

        genesis = BlockBuilder.genesis(wallets)
        self.chain: List[Block] = [genesis]
        self.balances: Dict[str, int] = {
            a["address"]: a["amount"] for a in genesis.allocations
        }
        self.next_nonce: Dict[str, int] = {a: 0 for a in self.balances}
        self.mempool: List[dict] = []  # не более одной от отправителя

        self._tx_verifier = TxVerifier(self.known_addresses)
        log.info("ledger initialized: wallets=%d genesis_hash=%s…",
                 len(wallets), genesis.block_hash[:12])

    # ─── отображение ────────────────────────────────────────────
    def name_of(self, address: str) -> str:
        return self._addr_name.get(address, address[:12] + "…")

    def dump(self) -> List[str]:
        last = self.chain[-1]
        out = [
            f"height = {last.index}",
            f"tip    = {last.block_hash}",
        ]
        for a in sorted(self.balances):
            out.append(
                f"  {self.name_of(a):<4} balance={self.balances[a]:>4}  "
                f"next_nonce={self.next_nonce[a]}"
            )
        out.append(f"  mempool: {len(self.mempool)} tx")
        return out

    # ─── снимок (неизменяемая копия) ────────────────────────────
    def snapshot(self) -> dict:
        return {
            "balances":        dict(self.balances),
            "next_nonce":      dict(self.next_nonce),
            "last_block":      self.chain[-1],
            "known_addresses": set(self.known_addresses),
        }

    # ─── условная рассылка транзакции ───────────────────────────
    def submit(self, tx: SignedTransaction,
               node_ids=("N0", "N1", "N2")) -> bool:
        """Передаёт копии транзакции трём узлам. При трёх OK — помещает
        одну копию в mempool."""
        if any(p["sender"] == tx.sender for p in self.mempool):
            log.warning("submit: у %s уже есть pending — отклоняем",
                        self.name_of(tx.sender))
            return False

        snap = self.snapshot()
        results = []
        for node in node_ids:
            local = copy.deepcopy(tx.to_dict())  # отдельная копия
            ok, reason = self._tx_verifier.verify(
                local, snap["balances"], snap["next_nonce"],
            )
            log.info("submit[%s]: %s — %s", node,
                     "ACCEPT" if ok else "REJECT", reason)
            results.append((node, ok, reason))

        if all(ok for _, ok, _ in results):
            self.mempool.append(copy.deepcopy(tx.to_dict()))
            log.info("mempool += %s… (len=%d)", tx.tx_id[:16],
                     len(self.mempool))
            return True
        return False

    # ─── применение блока ───────────────────────────────────────
    def apply(self, block: Block) -> None:
        for tx in block.transactions:
            self.balances[tx["sender"]]   -= tx["amount"]
            self.balances[tx["recipient"]] = \
                self.balances.get(tx["recipient"], 0) + tx["amount"]
            self.next_nonce[tx["sender"]] = tx["nonce"] + 1
        included = {t["tx_id"] for t in block.transactions}
        self.mempool = [m for m in self.mempool if m["tx_id"] not in included]
        self.chain.append(block)
        log.info("block %d applied: producer=%s  tip=%s…",
                 block.index, block.producer, block.block_hash[:12])
