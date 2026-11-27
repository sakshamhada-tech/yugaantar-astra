# Platform support: macOS (Apple Silicon) and Linux

You develop on macOS/arm64; judging runs on Linux/amd64. Every runtime
dependency must therefore install **without a compiler** on both, from a wheel.

## Read-only-rootfs check: Linux-only, and honest about it

`scripts/verify_container_contract.sh` bind-mounts the code directory read-only with
`unshare -r -m`. **`unshare` is Linux-only.** On macOS the script now detects this and
exits **77** with an explicit "NOT verified here" message, and
`scripts/phase1_acceptance.py` maps 77 to **SKIP**, not FAIL.

Why SKIP rather than FAIL: a missing capability is not a security finding. Reporting it
as FAIL trains the reader to ignore failures, which is how a real one gets missed.
Equally, it is never reported as PASS — the skip list prints it every run with the
reason, so it cannot be mistaken for green.

Verified in this repo both ways:

| Host | `unshare` present | Result |
| --- | --- | --- |
| Linux (this sandbox) | yes | full check runs, `all container-contract checks passed`, exit 0 |
| macOS | no | `== SKIPPED: read-only rootfs + temp-only state ==`, exit 77, gate records SKIP |
| Either, real breakage | — | gate still records **FAIL** (asserted with a simulated exit 1) |

To actually verify the container contract on a Mac, use Docker:

```sh
docker build -t pqc-kv:phase3 .
docker run --rm --read-only --tmpfs /tmp pqc-kv:phase3
```

`docker build` itself has never been executed in this environment (no daemon), which is
stated in `docs/EVIDENCE.md` rather than glossed over.

## Stated OS requirement in the adapter contract

`docs/adapter-v1.md` has exactly one OS-level statement, in "Process and state":

> "The judging runtime is an **offline Linux container** with Python 3.12,
> `pqcrypto==0.4.0` and Node.js 24.11.1. Its **root filesystem is read-only**.
> Use a writable temporary path for state that must survive between calls in the
> same container. Persist the application state before acknowledging a change.
> A fresh container starts empty. The local checker sets `TRACK4_STATE_DIR` for
> practice. In the judging container, fall back to the operating system's temp
> directory. The worker does not install dependencies from a submission during a
> run."

That is the whole of it. Concretely it imposes four things on us:

| Requirement | Where we handle it |
| --- | --- |
| Linux container, Python 3.12 | `Dockerfile` uses `python:3.12-slim-bookworm`; CI tests 3.12 (3.13 as canary) |
| Offline at run time, no dependency installs | all deps baked into the image; zero network calls in `src/` |
| Read-only root filesystem | no writes outside the state dir; verified by bind-mounting the code dir read-only |
| State in a temp path; `TRACK4_STATE_DIR` when set, else OS temp | `keystore.default_state_dir()`; the image deliberately does **not** set the variable, so the default command exercises the fallback path |

**Correction (verified 2026-11-26 against the PyPI JSON API):** an earlier version of
this document claimed `pqcrypto` ships **no** macOS arm64 wheel and that Apple Silicon
users needed Docker with `--platform linux/amd64`. That was wrong. Release 0.4.0
publishes seven macOS arm64 wheels (`cp39` through `cp314`), including
`pqcrypto-0.4.0-cp312-cp312-macosx_11_0_arm64.whl`. Native install on Apple Silicon
works; Docker is a convenience for reproducing the judge's linux/amd64 runtime, not a
requirement.

Notably, the document says **nothing about macOS**, and nothing about arm64 vs
amd64. Cross-platform support is therefore *our* requirement, and the only real
risk is dependency availability — which is exactly what the table below measures.

## Wheel availability (measured, not assumed)

Method: `pip download --only-binary=:all: --python-version 3.12 --implementation cp
--abi cp312 --platform <tag>` for each pin. If a package had to build from source,
the command fails; all commands below succeeded.

| Package | Version | linux/amd64 (manylinux_2_28) | linux/arm64 (manylinux_2_28) | macOS arm64 (11.0+) |
| --- | --- | --- | --- | --- |
| `pqcrypto` | 0.4.0 | `cp312 …manylinux_2_26_x86_64.manylinux_2_28_x86_64` | `cp312 …manylinux_2_26_aarch64.manylinux_2_28_aarch64` | `cp312 …macosx_11_0_arm64` |
| `cryptography` | 46.0.4 | `cp311-abi3 …manylinux_2_28_x86_64` | `cp311-abi3 …manylinux_2_28_aarch64` | `cp311-abi3 …macosx_10_9_universal2` (fat binary, runs on arm64) |
| `cffi` (dep of pqcrypto) | 2.1.1 | `cp312 …manylinux2014_x86_64` | `cp312 …manylinux2014_aarch64` | `cp312 …macosx_11_0_arm64` |
| `pycparser` (dep of cffi) | 3.12 | `py3-none-any` | `py3-none-any` | `py3-none-any` |

Notes worth knowing:

* `cryptography` is `abi3`, so one `cp311-abi3` wheel serves CPython 3.11 → 3.14.
  On Apple Silicon, pip picks the `universal2` fat wheel, which contains both
  arm64 and x86_64 slices — there is no separate arm64 file to worry about.
* `pqcrypto` has **no sdist**. If your platform/Python combination has no wheel,
  installation fails outright instead of trying to compile pqclean C sources. That
  is a good failure mode: it is loud and immediate, and the CI matrix exists to
  catch it before a judge does. Wheels exist for cp39–cp314 on all three targets.
* `pqcrypto` requires glibc ≥ 2.28 (`manylinux_2_28`). `python:3.12-slim-bookworm`
  is Debian 12 with glibc 2.36, so the image is comfortably inside that. Alpine
  (musl) also has wheels, but we do not use it.
* `cffi`'s wheels are tagged `manylinux2014` (an older baseline), so the binding
  layer works on even older glibc than `pqcrypto` itself needs.

## Verified on macOS — what exactly was and was not run

**Not run:** there is no macOS runner in this environment, so I could not execute
the suite on Apple Silicon. Do not take this document as "tested on your Mac".

**Run instead, and reproducible in one command here:**

```sh
# resolves and downloads every pin for cp312 on macOS arm64, wheels only
python3 -m pip download --no-deps --only-binary=:all: \
  --python-version 3.12 --implementation cp --abi cp312 \
  --platform macosx_11_0_arm64 -r requirements.txt
```

That is what produced the macOS column above: every pin *resolved to a wheel* for
`macosx_11_0_arm64` + cp312. Because both packages are prebuilt C extensions with
no C-level dependency on macOS frameworks we touch, and our own code is pure
Python using only `os`, `json`, `hashlib`, `hmac`, `subprocess`, `fcntl`, the
remaining macOS risk is small — but it is still **a risk I have not personally
measured on your machine**.

Two macOS-specific things to expect when you do run it:

1. **`fcntl.flock` works on macOS** (the store uses it as a single-writer lock).
   It is advisory on both platforms; behaviour is equivalent.
2. **`os.fsync` on a directory** is a no-op-ish op on macOS (it returns `EBADF`
   or succeeds without effect in some versions). `store._fsync_dir` and
   `keystore._fsync_dir` swallow `OSError` deliberately, so durability degrades
   gracefully rather than raising. The file-level `fsync` before `os.replace` is
   what actually matters, and that works identically.

**Do this once on your Mac to close the gap** (30 seconds, no Docker needed):

```sh
python3.12 -m venv .venv && . .venv/bin/activate
pip install --only-binary=:all: -r requirements.lock -r requirements-dev.lock
PYTHONPATH=src:. python -m pytest tests -q      # expect: 140 passed
```

If that prints `140 passed` (no skip — the skip only happens when
`cryptography` is missing), macOS support is confirmed on your hardware. Until
then the honest status is **"wheels exist for macOS arm64; suite not yet executed
there"**.

## Verified on Linux — actually run

| Check | Result |
| --- | --- |
| Wheels-only install of `requirements.lock` + `requirements-dev.lock`, CPython 3.11/3.12, linux/amd64 | ok, no compiler invoked |
| Full suite, `cryptography` backend | **139 passed, 1 skipped** |
| Full suite, `pycryptodome`-only venv (fallback path) | **140 passed** |
| Read-only code directory + no `TRACK4_STATE_DIR` + `HOME=/nonexistent` | setup / read / revoke / deny / audit all correct |
| Organizer validator in that same read-only, temp-only environment | **22 PASS, 0 FAIL**, "Local scenario passed." |
| `requirements.lock` resolved as pure wheels for linux/arm64 too | ok |

Reproduce:

```sh
./scripts/verify_container_contract.sh /path/to/Track-4-Toolkit
```

## The Docker image

`Dockerfile` targets `linux/amd64`, Python 3.12 slim (Debian bookworm), runs as
UID 10001, installs only prebuilt wheels (`PIP_ONLY_BINARY=:all:`), bakes all
dependencies in for offline use, and leaves `TRACK4_STATE_DIR` unset so the
default command exercises the OS-temp fallback the judge uses.

**Not built in this environment:** there is no Docker daemon here and no network
route to Docker Hub (`registry-1.docker.io` is unreachable), so I could not run
`docker build`. What I verified instead:

* the Dockerfile parses, and every `COPY` source exists in the build context;
* the build context contains **no** keys, state, `.env`, `__pycache__`, or
  organizer-toolkit files (31 files, `.dockerignore` applied);
* every pin resolves to a cp312 linux/amd64 wheel, so the `RUN pip install` layer
  cannot need a compiler or a source build;
* the runtime contract the image encodes (read-only code dir, temp-only state,
  unprivileged, no state variable) is executed and passing locally.

The `.github/workflows/verify.yml` `docker` job builds the image on a real Linux
runner, runs the suite inside it, hits it with `--read-only --tmpfs /tmp`, and runs
the organizer validator against the image. That job is the final proof; on the
first push it will either pass or tell us exactly which layer breaks.
