"""pqc-kv: post-quantum cryptography foundation for the Track 4 submission.

Public surface, in the order you would normally reach for it::

    from pqc_kv import kem, dsa, hybrid, envelope, keystore

    keys = kem.generate_keypair()                 # ML-KEM-768 recipient keys
    signer = dsa.generate_keypair()               # ML-DSA-65 signing keys
    env = envelope.seal(
        plaintext=b"...",
        recipient_public=keys,
        sender_signing_secret=signer.secret_key,
        recipient="asset:brief",
        envelope_id="env-1",
        context="pqc-kv/v1/asset-body",
    )
    body = envelope.open_envelope(
        env, recipient_secret=keys, sender_signing_public=signer.public_key
    )

Every primitive comes from a vetted library (pqcrypto / cryptography /
pycryptodome). Nothing in this package implements crypto maths.
"""

from __future__ import annotations

from . import aead, deps, dsa, envelope, hybrid, kem, keystore, symmetric

__all__ = ["aead", "deps", "dsa", "envelope", "hybrid", "kem", "keystore", "symmetric"]
__version__ = "1.0.0-phase1"
