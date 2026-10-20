"""Движок учебного консенсуса.

Три узла N0, N1, N2 получают один набор кандидатов и неизменяемый snapshot;
каждый независимо исключает некорректные блоки и голосует за блок с
лексикографически минимальным block_hash. Кворум — 2 из 3.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from pdlc.block import Block, BlockVerifier

log = logging.getLogger("pdlc.consensus")


class ConsensusStatus(str, Enum):
    ACCEPTED  = "ACCEPTED"
    NO_QUORUM = "NO_QUORUM"


@dataclass
class VoteRound:
    status: ConsensusStatus
    votes:  Dict[str, Optional[str]]
    winner: Optional[Block]


class ConsensusEngine:

    def __init__(self, known_addresses: Set[str],
                 node_ids: Tuple[str, ...] = ("N0", "N1", "N2"),
                 quorum: int = 2) -> None:
        self.verifier = BlockVerifier(known_addresses)
        self.node_ids = node_ids
        self.quorum   = quorum

    def _node_vote(self, node: str, candidates: List[Block],
                   snapshot: dict) -> Optional[str]:
        valid: List[Block] = []
        seen_hashes: set[str] = set()
        for cand in candidates:
            if cand.block_hash in seen_hashes:
                continue
            seen_hashes.add(cand.block_hash)
            ok, reason = self.verifier.verify(
                cand, snapshot["last_block"],
                snapshot["balances"], snapshot["next_nonce"],
            )
            log.info("[%s] %s (%s…) → %s%s", node, cand.producer,
                     cand.block_hash[:12], "OK" if ok else "REJECT",
                     "" if ok else f" ({reason})")
            if ok:
                valid.append(cand)
        if not valid:
            log.info("[%s] NO_VOTE", node)
            return None
        chosen = min(valid, key=lambda b: b.block_hash)
        log.info("[%s] vote → %s…", node, chosen.block_hash[:12])
        return chosen.block_hash

    def decide(self, candidates: List[Block], snapshot: dict) -> VoteRound:
        votes = {n: self._node_vote(n, candidates, snapshot)
                 for n in self.node_ids}

        tally: Dict[str, int] = {}
        for v in votes.values():
            if v is not None:
                tally[v] = tally.get(v, 0) + 1
        log.info("tally = %s", tally)

        winner_hash = next(
            (h for h, c in tally.items() if c >= self.quorum), None,
        )
        if winner_hash is None:
            return VoteRound(ConsensusStatus.NO_QUORUM, votes, None)
        winner = next(c for c in candidates if c.block_hash == winner_hash)
        return VoteRound(ConsensusStatus.ACCEPTED, votes, winner)
