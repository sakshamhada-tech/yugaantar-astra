"""Key storage: permissions, atomicity, corruption handling, no leakage."""

from __future__ import annotations

import json
import os
import stat

import pytest

from pqc_kv import keystore
from pqc_kv.keystore import KeyStore, KeyStoreError, default_state_dir


def test_default_state_dir_honours_contract_variable(state_dir):
    assert default_state_dir() == state_dir


def test_created_directory_is_private(tmp_path):
    directory = keystore.ensure_private_dir(tmp_path / "state" / "keys")
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700


def test_permissions_are_tightened_when_too_open(tmp_path):
    loose = tmp_path / "loose"
    loose.mkdir()
    os.chmod(loose, 0o755)
    tightened = keystore.ensure_private_dir(loose)
    assert stat.S_IMODE(tightened.stat().st_mode) == 0o700


def test_key_file_is_created_mode_600(tmp_path):
    store = KeyStore(tmp_path / "keys")
    store.kem_keypair("asset-store")
    path = tmp_path / "keys" / "kem-asset-store.key"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_key_file_with_open_permissions_is_refused(tmp_path):
    store = KeyStore(tmp_path / "keys")
    store.kem_keypair("asset-store")
    path = tmp_path / "keys" / "kem-asset-store.key"
    os.chmod(path, 0o644)
    with pytest.raises(KeyStoreError):
        keystore.read_key_file(path)


def test_keys_persist_and_reload(tmp_path):
    first = KeyStore(tmp_path / "keys").kem_keypair("asset-store")
    second = KeyStore(tmp_path / "keys").kem_keypair("asset-store")
    assert first.public_key == second.public_key
    assert first.secret_key == second.secret_key


def test_distinct_labels_get_distinct_keys(tmp_path):
    store = KeyStore(tmp_path / "keys")
    assert store.kem_keypair("a").public_key != store.kem_keypair("b").public_key
    assert store.signing_keypair("a").public_key != store.signing_keypair("b").public_key


def test_corrupt_key_file_rejected(tmp_path):
    path = tmp_path / "keys" / "kem-asset-store.key"
    keystore.ensure_private_dir(tmp_path / "keys")
    path.write_text("{}", encoding="utf-8")
    os.chmod(path, 0o600)
    with pytest.raises(KeyStoreError):
        keystore.read_key_file(path)


def test_truncated_key_file_rejected(tmp_path):
    store = KeyStore(tmp_path / "keys")
    store.kem_keypair("asset-store")
    path = tmp_path / "keys" / "kem-asset-store.key"
    path.write_text(path.read_text(encoding="utf-8")[:20], encoding="utf-8")
    with pytest.raises(KeyStoreError):
        keystore.read_key_file(path)


def test_no_temp_files_left_behind(tmp_path):
    store = KeyStore(tmp_path / "keys")
    store.kem_keypair()
    store.signing_keypair()
    store.hybrid_keypair()
    leftovers = [p.name for p in (tmp_path / "keys").iterdir() if p.name.startswith(".tmp")]
    assert leftovers == []


def test_hybrid_keys_round_trip(tmp_path):
    first = KeyStore(tmp_path / "keys").hybrid_keypair("asset-store")
    second = KeyStore(tmp_path / "keys").hybrid_keypair("asset-store")
    assert first.x25519_secret == second.x25519_secret
    assert first.mlkem_secret == second.mlkem_secret


def test_error_messages_contain_no_key_bytes(tmp_path):
    store = KeyStore(tmp_path / "keys")
    pair = store.kem_keypair()
    path = tmp_path / "keys" / "kem-asset-store.key"
    path.write_text("garbage", encoding="utf-8")
    with pytest.raises(KeyStoreError) as info:
        keystore.read_key_file(path)
    message = str(info.value)
    assert pair.secret_key.hex() not in message
    assert len(message) < 120


def test_files_are_valid_json_with_magic(tmp_path):
    store = KeyStore(tmp_path / "keys")
    store.signing_keypair("svc")
    data = json.loads((tmp_path / "keys" / "dsa-svc.key").read_text(encoding="utf-8"))
    assert data["magic"] == keystore.KEY_MAGIC
    assert data["key_version"] == keystore.KEY_FORMAT_VERSION
