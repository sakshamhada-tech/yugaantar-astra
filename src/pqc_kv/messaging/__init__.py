"""Phase 2: authenticated post-quantum messaging on top of the Phase 1 primitives.

Nothing here implements a primitive. The pieces are compositions of what
``pqc_kv`` already provides:

    ML-KEM-768 / ML-DSA-65     -> pqc_kv.kem / pqc_kv.dsa
    X25519 + ML-KEM hybrid DH  -> pqc_kv.hybrid
    HKDF-SHA256                -> pqc_kv.symmetric.hkdf_sha256
    AES-256-GCM                -> pqc_kv.symmetric
    nonce policy + AAD builder -> pqc_kv.aead
    atomic key files, flock    -> pqc_kv.keystore / pqc_kv.store

Protocol in one sentence: two parties prove who they are with long-term ML-DSA
signatures over a handshake transcript, mix ephemeral X25519 and ephemeral
ML-KEM secrets into a root key, and ratchet that root key with HKDF into
per-direction chain keys and per-message keys. Each message is authenticated
end-to-end (signature + AEAD + AAD binding the recipient), and large messages are
fragmented so loss and reordering can be tolerated per fragment.

Deliberate non-goals, stated so nobody has to guess: no DH ratchet (so no
post-compromise security), no group messaging, no cover traffic, no trusted clock.
"""

from __future__ import annotations

__all__ = [
    "directory",
    "ephemeral",
    "identity",
    "kdf",
    "session",
    "wire",
]
__version__ = "2.0.0-phase2"
