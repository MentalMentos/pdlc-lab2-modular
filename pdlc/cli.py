"""CLI-демо: контрольный сценарий + отрицательные проверки."""

from __future__ import annotations

import copy
import json
import logging

from pdlc.block import Block, BlockBuilder
from pdlc.consensus import ConsensusEngine, ConsensusStatus
from pdlc.crypto import KeyPair, canonical_json, sha256_hex, verify
from pdlc.merkle import MerkleTree
from pdlc.state import Ledger
from pdlc.tx import TxBuilder, TxValidationError
from pdlc.wallet import Wallet


def _step(title: str) -> None:
    print()
    print("━" * 76)
    print(f"  {title}")
    print("━" * 76)


def _show_state(ledger: Ledger, note: str = "") -> None:
    if note:
        print(f"\n── {note} ──")
    for line in ledger.dump():
        print(line)


def run_demo() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="  log %(name)-16s %(levelname)-5s %(message)s",
    )

    # ──────────────────────────────────────────────────────────
    _step("ЭТАП I — Генерация кошельков и инициализация реестра")
    A = Wallet.new("A")
    B = Wallet.new("B")
    C = Wallet.new("C")
    for w in (A, B, C):
        print(f"  {w.name}: pub = {w.public_hex}")
        print(f"      addr = SHA-256(pub) = {w.address}")

    ledger = Ledger([A, B, C])
    _show_state(ledger, "Начальное состояние (из allocations)")
    print(f"\n  genesis.block_hash = {ledger.chain[0].block_hash}")

    # ──────────────────────────────────────────────────────────
    _step("ЭТАП II — Проверка подписи сообщения")
    msg1 = b"Blockchain lab 2"
    msg2 = b"Blockchain lab 3"
    sig  = A.keypair.sign(msg1).hex()
    print(f"  подписали ключом A сообщение 'Blockchain lab 2'")
    print(f"  signature = {sig}")
    print(f"  verify(A.pub, msg1, sig) = {verify(A.public_hex, msg1, sig)}   (True)")
    print(f"  verify(A.pub, msg2, sig) = {verify(A.public_hex, msg2, sig)}   (False)")
    print(f"  verify(B.pub, msg1, sig) = {verify(B.public_hex, msg1, sig)}   (False)")

    # ──────────────────────────────────────────────────────────
    _step("ЭТАП III — Контрольный сценарий A→B 10, B→C 20, C→A 5")
    tx1 = TxBuilder.build(A, B.address, 10, nonce=0)
    tx2 = TxBuilder.build(B, C.address, 20, nonce=0)
    tx3 = TxBuilder.build(C, A.address, 5,  nonce=0)
    for lbl, tx in [("tx1 A→B 10", tx1), ("tx2 B→C 20", tx2),
                    ("tx3 C→A 5",  tx3)]:
        print(f"\n[{lbl}]")
        ledger.submit(tx)

    _show_state(ledger, "После добавления в mempool")
    print("\n  Пример полной подписанной транзакции (tx1):")
    print(json.dumps(tx1.to_dict(), indent=2, ensure_ascii=False))

    # ──────────────────────────────────────────────────────────
    _step("ЭТАП IV — Дерево Меркла для 1, 2 и 3 транзакций")
    for size, batch in [(1, [tx1]), (2, [tx1, tx2]), (3, [tx1, tx2, tx3])]:
        print(f"\n[{size} транзакц.]")
        tree = MerkleTree([t.to_dict() for t in batch])
        for line in tree.pretty_print():
            print(line)

    # ──────────────────────────────────────────────────────────
    _step("ЭТАП V — Конфликт B1, B2, B3 и голосование")
    last = ledger.chain[-1]
    txs_direct  = [tx1.to_dict(), tx2.to_dict(), tx3.to_dict()]
    txs_reverse = [tx3.to_dict(), tx2.to_dict(), tx1.to_dict()]

    B1 = BlockBuilder.build(last.index + 1, last.block_hash, "P1", txs_direct)
    B2 = BlockBuilder.build(last.index + 1, last.block_hash, "P2", txs_reverse)

    # B3 — копия B1 с подменой amount и пересчётом tx_id + merkle_root,
    # но исходной подписью
    tx1_bad = copy.deepcopy(tx1.to_dict())
    tx1_bad["amount"] = 99
    body_bad = {k: tx1_bad[k] for k in
                ("sender", "recipient", "amount", "nonce", "public_key")}
    tx1_bad["tx_id"] = sha256_hex(canonical_json(body_bad))
    B3 = BlockBuilder.build(last.index + 1, last.block_hash, "P3",
                            [tx1_bad, tx2.to_dict(), tx3.to_dict()])

    for lbl, b in [("B1", B1), ("B2", B2), ("B3", B3)]:
        print(f"\n  {lbl}: producer={b.producer}  index={b.index}  "
              f"prev_hash={b.prev_hash[:12]}…")
        print(f"      merkle_root = {b.merkle_root}")
        print(f"      block_hash  = {b.block_hash}")

    print("\n[голосование]")
    engine = ConsensusEngine(ledger.known_addresses)
    result = engine.decide([B1, B2, B3], ledger.snapshot())
    print(f"  status = {result.status.value}")
    assert result.status == ConsensusStatus.ACCEPTED
    print(f"  winner = {result.winner.producer} "
          f"(hash {result.winner.block_hash[:12]}…)")
    ledger.apply(result.winner)
    _show_state(ledger, f"После принятия (producer={result.winner.producer})")

    # ──────────────────────────────────────────────────────────
    _step("ЭТАП VI — Отрицательные проверки (таблица 2 ТЗ)")

    print("\n[VI.1] Перестановка кандидатов — итог не меняется")
    tx4 = TxBuilder.build(A, B.address, 1, nonce=ledger.next_nonce[A.address])
    tx5 = TxBuilder.build(B, C.address, 1, nonce=ledger.next_nonce[B.address])
    ledger.submit(tx4); ledger.submit(tx5)
    last = ledger.chain[-1]
    cx = BlockBuilder.build(last.index + 1, last.block_hash, "PX",
                            [tx4.to_dict(), tx5.to_dict()])
    cy = BlockBuilder.build(last.index + 1, last.block_hash, "PY",
                            [tx5.to_dict(), tx4.to_dict()])
    r1 = engine.decide([cx, cy], ledger.snapshot())
    r2 = engine.decide([cy, cx], ledger.snapshot())
    assert r1.winner.block_hash == r2.winner.block_hash
    print(f"  → итог одинаков: {r1.winner.block_hash[:12]}…")
    ledger.apply(r1.winner)

    print("\n[VI.2] Подмена amount при сохранённой подписи")
    base = TxBuilder.build(A, B.address, 1,
                           nonce=ledger.next_nonce[A.address]).to_dict()
    tampered = dict(base); tampered["amount"] = 99
    body_t = {k: tampered[k] for k in
              ("sender", "recipient", "amount", "nonce", "public_key")}
    tampered["tx_id"] = sha256_hex(canonical_json(body_t))
    from pdlc.tx import TxVerifier
    tv = TxVerifier(ledger.known_addresses)
    ok, reason = tv.verify(tampered, ledger.balances, ledger.next_nonce)
    print(f"  verify = {ok}  reason = {reason}")

    print("\n[VI.3] Недопустимые суммы 0 / -1 / 1.5 / True")
    for bad in (0, -1, 1.5, True):
        try:
            TxBuilder.build(A, B.address, bad,
                            nonce=ledger.next_nonce[A.address])
            print(f"  amount={bad!r} → ОШИБКА: пропущено (должно быть rejected)")
        except TxValidationError as exc:
            print(f"  amount={bad!r} → отклонено: {exc}")

    print("\n[VI.4] Перерасход баланса")
    overspend = TxBuilder.build(A, B.address, 10000,
                                nonce=ledger.next_nonce[A.address]).to_dict()
    ok, reason = tv.verify(overspend, ledger.balances, ledger.next_nonce)
    print(f"  verify = {ok}  reason = {reason}")

    print("\n[VI.5] Повтор по nonce (nonce=0 для A уже использован)")
    replay = TxBuilder.build(A, B.address, 1, nonce=0).to_dict()
    ok, reason = tv.verify(replay, ledger.balances, ledger.next_nonce)
    print(f"  verify = {ok}  reason = {reason}")

    print("\n[VI.6] Вторая pending того же отправителя")
    ledger.mempool.clear()
    ok1 = ledger.submit(TxBuilder.build(
        A, B.address, 1, nonce=ledger.next_nonce[A.address]))
    ok2 = ledger.submit(TxBuilder.build(
        A, B.address, 2, nonce=ledger.next_nonce[A.address] + 1))
    print(f"  mempool len = {len(ledger.mempool)}   (ожидали 1)")
    ledger.mempool.clear()

    print("\n[VI.7] Все кандидаты некорректны → NO_QUORUM")
    broken = Block(
        index=cx.index, prev_hash=cx.prev_hash, producer=cx.producer,
        merkle_root=cx.merkle_root, transactions=cx.transactions,
        block_hash="ff" * 32,
    )
    r = engine.decide([broken], ledger.snapshot())
    print(f"  status = {r.status.value}   (ожидали NO_QUORUM)")

    # ──────────────────────────────────────────────────────────
    _step("ЭТАП VII — Итоговое состояние")
    _show_state(ledger)
    total = sum(ledger.balances.values())
    print(f"\n  суммарный баланс = {total}  (должно быть 300)")


if __name__ == "__main__":
    run_demo()
