"""Dependency gate.

The judging container is a read-only, offline Linux box with Python 3.12 and
``pqcrypto==0.4.0``. It will NOT install our ``requirements.txt`` for us, and it
may or may not carry a symmetric-crypto package (``cryptography``).

So we never guess: this module probes what is actually importable and exposes a
single place that says which AES-GCM / HKDF / X25519 backend is live. Each
backend is a vetted library. We never implement a primitive here.

Selection order for symmetric crypto + X25519:

    1. ``cryptography``      (preferred: one library covers all three)
    2. ``pycryptodome``      (fallback: also covers all three)
    3. builtin ``hmac``/``hashlib`` for HKDF only, with AES-GCM and X25519
       reported as unavailable.

If no AES-GCM backend exists we degrade explicitly (see ``CAPABILITIES``) instead
of shipping a home-made cipher.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Backend:
    """Names of the libraries we resolved."""

    symmetric: str  # "cryptography" | "pycryptodome" | "none"
    pqcrypto: str | None  # "pqcrypto" version string if importable

    @property
    def has_aead(self) -> bool:
        return self.symmetric in ("cryptography", "pycryptodome")

    @property
    def has_x25519(self) -> bool:
        return self.symmetric in ("cryptography", "pycryptodome")

    @property
    def has_pq(self) -> bool:
        return self.pqcrypto is not None

    def describe(self) -> dict[str, Any]:
        return {
            "symmetric": self.symmetric,
            "aead": self.has_aead,
            "x25519": self.has_x25519,
            "pqcrypto": self.pqcrypto,
        }


def _version(module_name: str) -> str | None:
    try:
        import importlib.metadata as md

        return md.version(module_name)
    except Exception:  # pragma: no cover - metadata can be absent in odd builds
        return None


def _try_import(name: str) -> bool:
    try:
        importlib.import_module(name)
        return True
    except Exception:
        return False


def _detect() -> Backend:
    pq = _version("pqcrypto") if _try_import("pqcrypto") else None

    # cryptography: needs the AEAD and X25519 surfaces we use.
    if _try_import("cryptography.hazmat.primitives.ciphers.aead") and _try_import(
        "cryptography.hazmat.primitives.asymmetric.x25519"
    ):
        return Backend(symmetric="cryptography", pqcrypto=pq)

    if _try_import("Crypto.Cipher.AES") and _try_import("Crypto.Protocol.KDF"):
        return Backend(symmetric="pycryptodome", pqcrypto=pq)

    return Backend(symmetric="none", pqcrypto=pq)


BACKEND: Backend = _detect()


class Unavailable(RuntimeError):
    """Raised when a requested capability has no vetted backend present."""


def require_aead() -> None:
    if not BACKEND.has_aead:
        raise Unavailable(
            "No AES-GCM backend found. Install one of: cryptography, pycryptodome. "
            "This build intentionally has no fallback cipher."
        )


def require_pq() -> None:
    if not BACKEND.has_pq:
        raise Unavailable("pqcrypto (ML-KEM/ML-DSA) is not importable in this environment.")
