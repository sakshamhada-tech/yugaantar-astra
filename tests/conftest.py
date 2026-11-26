"""Shared fixtures. Tests never touch the network and never write outside tmp dirs."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture()
def state_dir(tmp_path, monkeypatch):
    """Isolated state directory, exactly like the adapter contract's variable."""
    target = tmp_path / "state"
    target.mkdir()
    monkeypatch.setenv("TRACK4_STATE_DIR", str(target))
    return target


@pytest.fixture()
def kem_keys():
    from pqc_kv import kem

    return kem.generate_keypair()


@pytest.fixture()
def signing_keys():
    from pqc_kv import dsa

    return dsa.generate_keypair()


@pytest.fixture()
def hybrid_keys():
    from pqc_kv import hybrid

    return hybrid.generate_keypair()


def flip_bit(data: bytes, index: int = 0, bit: int = 0) -> bytes:
    """Return a copy of ``data`` with one bit flipped. The core tamper tool."""
    if not data:
        raise ValueError("cannot flip a bit in empty data")
    mutable = bytearray(data)
    mutable[index % len(mutable)] ^= 1 << bit
    return bytes(mutable)


@pytest.fixture()
def bitflip():
    return flip_bit


@pytest.fixture()
def clean_env(monkeypatch):
    """Remove any inherited adapter state variable so tests are hermetic."""
    for name in ("TRACK4_STATE_DIR", "TMPDIR", "TEMP", "TMP"):
        monkeypatch.delenv(name, raising=False)
    return os.environ
