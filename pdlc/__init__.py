"""pdlc — учебный консольный блокчейн (ЛР №2, альтернативная реализация).

Разбит на модули:
    pdlc.crypto     — Ed25519, SHA-256, канонический JSON
    pdlc.wallet     — класс Wallet
    pdlc.tx         — Transaction, TxBuilder, TxVerifier
    pdlc.merkle     — MerkleTree
    pdlc.block      — Block, BlockBuilder, BlockVerifier
    pdlc.state      — Ledger (balances + nonces + chain + mempool)
    pdlc.consensus  — ConsensusEngine с голосованием узлов
    pdlc.cli        — демо-сценарий
"""

__version__ = "1.0.0"
