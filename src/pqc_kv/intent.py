"""Write-ahead intent records, and a fault-injection hook that cannot be abused.

The problem
-----------
Rotation touches many things: a new key version, every asset envelope, the ring, and
the state file. A process can die anywhere in the middle -- the judging container
starts a fresh process per request, so "it died mid-rotation" is the normal case, not
an exotic one. If we simply did the work, a crash would leave some assets on version
N and some on N+1 with no record of which was intended.

The fix: a checklist written *before* the work
----------------------------------------------
    1. write intent.json   "I am rotating v1 -> v2, these asset ids are in scope"
    2. do the work
    3. write commit marker "v2 is live, intent done"
    4. delete the intent

Recovery reads that and lands on exactly one version:

    no intent                      -> nothing to do
    intent, no commit, version N   -> the rotation never became live: finish it
                                      forward (re-wrap anything left, then commit),
                                      because re-wrapping is idempotent
    intent + commit                -> the work is done: just clear the intent

Why "finish forward" rather than "roll back"
--------------------------------------------
Re-sealing an asset under the new version is idempotent, and version N+1 is already
created, so finishing is one code path with no special cases. Rolling back would have
to un-create a version and re-seal backwards, doubling the failure surface for nothing.
The rule that matters is *one consistent, authorized version*, which both directions
give; this one is cheaper to get right.

Revocations are never touched by a rotation, so recovery cannot un-revoke anyone:
revoked names live in `state["disabled"]`, which the intent never rewrites.

The fault hook
--------------
``TRACK4_FAULT_AT`` names a point (``before_intent``, ``after_intent``,
``mid_rewrap``, ``before_commit``, ``after_commit``) and the process exits immediately
when it reaches it, in the middle of a write where possible.

Two hard constraints, both enforced in code and tested:

* It is read from the **environment only**. ``team_app`` scrubs the variable out of
  ``os.environ`` at import, so no code path downstream -- including a future bug --
  can set it from an adapter request.
* It is **off** unless set to one of the five known names. A typo or an unknown value
  does nothing, so it cannot be discovered and steered by guessing.

The hook is a test instrument. It is not a feature, and it never appears in any op.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

INTENT_MAGIC = "pqc-kv-intent"
INTENT_VERSION = 1
FAULT_ENV = "TRACK4_FAULT_AT"

#: Named points where a crash can be injected. Anything else is ignored.
FAULT_POINTS = (
    "before_intent",
    "after_intent",
    "mid_rewrap",
    "before_commit",
    "after_commit",
)


class IntentError(Exception):
    """Intent record problem. No key material, no plaintext."""


def _fault_env_was_present() -> bool:
    """Whether the hook was requested at import time (before team_app scrubbed it)."""
    return bool(os.environ.get(FAULT_ENV))


#: Captured at import so scrubbing the variable later cannot hide the request.
_FAULT_WANTED = _fault_env_was_present()


def fault_point(name: str) -> None:
    """Abort the process if the hook names this point. No-op otherwise."""
    if not _FAULT_WANTED:
        return
    wanted = os.environ.get(FAULT_ENV) or _scrubbed_value
    if wanted != name:
        return
    # Hard exit, no cleanup, no flush: this must look like a power cut, not a
    # polite shutdown. Buffers that were not fsynced are genuinely lost.
    os._exit(97)


#: team_app moves the value here before scrubbing the environment.
_scrubbed_value: str | None = None


def take_fault_configuration() -> str | None:
    """Move the hook's value out of the environment and return it.

    Called once by ``team_app`` at import: the value is kept in a module global for
    :func:`fault_point`, and ``os.environ[FAULT_ENV]`` is deleted so nothing that a
    request could influence is left readable in the environment.
    """
    global _scrubbed_value
    value = os.environ.pop(FAULT_ENV, None)
    _scrubbed_value = value if value in FAULT_POINTS else None
    return _scrubbed_value


def fault_enabled() -> bool:
    return _scrubbed_value is not None


# ------------------------------------------------------------------- records
def intent_path(root: Path) -> Path:
    return Path(root) / "intent.json"


def commit_path(root: Path) -> Path:
    return Path(root) / "intent.commit"


def read_intent(root: Path) -> dict | None:
    path = intent_path(root)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise IntentError("intent record unreadable") from None
    if not isinstance(data, dict) or data.get("magic") != INTENT_MAGIC:
        raise IntentError("intent record is not ours")
    if data.get("version") != INTENT_VERSION:
        raise IntentError("unsupported intent version")
    return data


def write_intent(root: Path, payload: dict) -> None:
    body = dict(payload, magic=INTENT_MAGIC, version=INTENT_VERSION)
    _atomic_write(intent_path(root), json.dumps(body, sort_keys=True, separators=(",", ":")))


def write_commit(root: Path, payload: dict) -> None:
    body = dict(payload, magic=INTENT_MAGIC, version=INTENT_VERSION)
    _atomic_write(commit_path(root), json.dumps(body, sort_keys=True, separators=(",", ":")))


def read_commit(root: Path) -> dict | None:
    path = commit_path(root)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise IntentError("commit marker unreadable") from None
    if not isinstance(data, dict) or data.get("magic") != INTENT_MAGIC:
        raise IntentError("commit marker is not ours")
    return data


def clear(root: Path) -> None:
    """Remove the intent and the commit marker. Order: commit first.

    If we die between the two unlinks we have a commit with no intent, which recovery
    already treats as a no-op -- so the only bad order would be the reverse.
    """
    for path in (commit_path(root), intent_path(root)):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            raise IntentError("cannot clear intent record") from None
    _fsync_dir(Path(root))


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=str(path.parent), prefix=".intent-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        name = None
        _fsync_dir(path.parent)
    except OSError:
        raise IntentError("cannot write intent record") from None
    finally:
        if name is not None:
            try:
                os.unlink(name)
            except OSError:
                pass


def _fsync_dir(directory: Path) -> None:
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


__all__ = [
    "FAULT_ENV", "FAULT_POINTS", "IntentError",
    "clear", "fault_enabled", "fault_point", "intent_path",
    "read_commit", "read_intent", "take_fault_configuration",
    "write_commit", "write_intent",
]
