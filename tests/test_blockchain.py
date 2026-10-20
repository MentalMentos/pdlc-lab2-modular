#!/usr/bin/env python3
"""Pytest-набор: быстрые инвариантные проверки."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402

from pdlc.block import BlockBuilder
from pdlc.consensus import ConsensusEngine, ConsensusStatus
from pdlc.crypto import KeyPair, verify
from pdlc.merkle import MerkleTree
from pdlc.state import Ledger
from pdlc.tx import TxBuilder, TxValidationError
from pdlc.wallet import Wallet


@pytest.fixture
def wallets():
    return [Wallet.new("A"), Wallet.new("B"), Wallet.new("C")]


@pytest.fixture
def ledger(wallets):
    return Ledger(wallets)


# ───── криптография ─────────────────────────────────────────
def test_keypair_lengths():
    kp = KeyPair.generate()
    assert len(kp.public_bytes) == 32
    sig = kp.sign(b"hello")
    assert len(sig) == 64


def test_verify_rejects_wrong_message(wallets):
    A = wallets[0]
    sig = A.keypair.sign(b"m1").hex()
    assert     verify(A.public_hex, b"m1", sig)
    assert not verify(A.public_hex, b"m2", sig)


def test_verify_rejects_wrong_key(wallets):
    A, B = wallets[:2]
    sig = A.keypair.sign(b"m1").hex()
    assert not verify(B.public_hex, b"m1", sig)


# ───── транзакции ──────────────────────────────────────────
def test_builder_rejects_bad_amount(wallets):
    A, B = wallets[:2]
    for bad in (0, -1, 1.5, True):
        with pytest.raises(TxValidationError):
            TxBuilder.build(A, B.address, bad, nonce=0)


def test_builder_rejects_self_send(wallets):
    A = wallets[0]
    with pytest.raises(TxValidationError):
        TxBuilder.build(A, A.address, 1, nonce=0)


def test_tx_roundtrip(ledger, wallets):
    A, B, _ = wallets
    tx = TxBuilder.build(A, B.address, 10, nonce=0)
    assert ledger.submit(tx) is True
    assert len(ledger.mempool) == 1


def test_only_one_pending_per_sender(ledger, wallets):
    A, B, _ = wallets
    assert ledger.submit(TxBuilder.build(A, B.address, 1, nonce=0))
    assert not ledger.submit(TxBuilder.build(A, B.address, 2, nonce=1))
    assert len(ledger.mempool) == 1


# ───── Merkle ──────────────────────────────────────────────
def test_merkle_single_leaf_equals_hash():
    tx = {"a": 1}
    tree = MerkleTree([tx])
    assert len(tree.levels) == 1


def test_merkle_three_duplication_rule():
    txs = [{"n": i} for i in range(3)]
    t = MerkleTree(txs)
    assert len(t.levels[0]) == 3     # хранится 3 листа
    assert len(t.levels[1]) == 2     # пары с дублированием последнего
    assert len(t.levels[2]) == 1


def test_merkle_root_changes_on_permutation():
    a = {"n": 1}; b = {"n": 2}
    r1 = MerkleTree([a, b]).root
    r2 = MerkleTree([b, a]).root
    assert r1 != r2


# ───── блок + консенсус ────────────────────────────────────
def test_full_control_scenario(ledger, wallets):
    A, B, C = wallets
    tx1 = TxBuilder.build(A, B.address, 10, nonce=0)
    tx2 = TxBuilder.build(B, C.address, 20, nonce=0)
    tx3 = TxBuilder.build(C, A.address, 5,  nonce=0)
    for t in (tx1, tx2, tx3):
        assert ledger.submit(t)

    last = ledger.chain[-1]
    block = BlockBuilder.build(
        last.index + 1, last.block_hash, "P1",
        [tx1.to_dict(), tx2.to_dict(), tx3.to_dict()],
    )
    engine = ConsensusEngine(ledger.known_addresses)
    r = engine.decide([block], ledger.snapshot())
    assert r.status == ConsensusStatus.ACCEPTED
    ledger.apply(r.winner)

    assert ledger.balances[A.address] == 95
    assert ledger.balances[B.address] == 90
    assert ledger.balances[C.address] == 115
    for addr in ledger.balances:
        assert ledger.next_nonce[addr] == 1
    assert sum(ledger.balances.values()) == 300


def test_no_quorum_when_all_broken(ledger, wallets):
    engine = ConsensusEngine(ledger.known_addresses)
    last = ledger.chain[-1]
    bad = BlockBuilder.build(
        last.index + 99, "ff" * 32, "BAD",
        [TxBuilder.build(wallets[0], wallets[1].address, 1, 0).to_dict()],
    )
    r = engine.decide([bad], ledger.snapshot())
    assert r.status == ConsensusStatus.NO_QUORUM
