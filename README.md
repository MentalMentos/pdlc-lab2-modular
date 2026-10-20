# pdlc-lab2-modular — учебный блокчейн (модульная OOP-реализация)

Альтернативная реализация **ЛР №2** по дисциплине «Программное обеспечение
систем распределённого реестра» для **варианта 8** постановки.

Автор: **Королев Роман Игоревич**, группа **ИКПИ-31**.
Руководитель: Помогалова А. В.

## Чем отличается от первой реализации

| Аспект                 | Эта версия                                      |
|------------------------|-------------------------------------------------|
| Криптография Ed25519   | **PyNaCl** (`nacl.signing`), RFC 8032           |
| Организация кода       | **модульная**, пакет `pdlc/`                    |
| Стиль                  | **классы, dataclasses, type hints, свойства**   |
| Логирование            | модуль `logging` (уровни), **без print в ядре** |
| Тесты                  | **pytest-набор** (12 тестов) в `tests/`         |
| Точка входа            | `main.py` → `pdlc.cli.run_demo()`               |

## Структура пакета

```
pdlc-lab2-modular/
├── main.py                 — точка входа
├── pdlc/
│   ├── __init__.py
│   ├── crypto.py           — Ed25519 (PyNaCl), SHA-256, canonical JSON
│   ├── wallet.py           — class Wallet (dataclass + cached_property)
│   ├── tx.py               — SignedTransaction / TxBuilder / TxVerifier
│   ├── merkle.py           — class MerkleTree
│   ├── block.py            — Block / BlockBuilder / BlockVerifier
│   ├── state.py            — Ledger (chain + balances + mempool)
│   ├── consensus.py        — ConsensusEngine, VoteRound, enum ConsensusStatus
│   └── cli.py              — демо-сценарий
├── tests/
│   └── test_blockchain.py  — 12 pytest-тестов
└── README.md
```

## Запуск

```bash
pip install pynacl pytest
python3 main.py           # демо
python3 -m pytest tests/  # 12/12 passed
```

## Контрольный сценарий

A → B 10, B → C 20, C → A 5. Ожидаемый результат:

| адрес | balance | next_nonce |
|-------|---------|------------|
| A     | 95      | 1          |
| B     | 90      | 1          |
| C     | 115     | 1          |

Суммарный баланс не меняется — 300.

## Отличие в деталях реализации

* `Wallet` — frozen dataclass; адрес — `cached_property`.
* `SignedTransaction` — frozen dataclass с `to_dict`/`from_dict`.
* `MerkleTree` — всё состояние хранится как `levels`, доступно для вывода.
* `Ledger` — публичные методы `submit()`, `apply()`, `snapshot()`, `dump()`.
* `ConsensusEngine` принимает `node_ids` и `quorum` как параметры конструктора,
  возвращает dataclass `VoteRound` со статусом `ConsensusStatus`.
* Все отрицательные проверки работают через **исключение** `TxValidationError`
  (где это уместно) или через возврат `(False, reason)`.
