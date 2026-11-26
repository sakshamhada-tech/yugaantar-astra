# syntax=docker/dockerfile:1
#
# Phase 1 image: Python 3.12 on linux/amd64, offline-capable at run time.
#
# Build (from this directory):
#   docker build --platform linux/amd64 -t pqc-kv:phase1 .
#
# Run the adapter exactly the way the judging worker does (one process,
# one JSON object on stdin, state in a writable temp dir):
#   echo '{"op":"setup","owners":{"brief":"maya"},"contents":{"brief":"demo"}}' \
#     | docker run --rm -i --read-only --tmpfs /tmp pqc-kv:phase1
#
# Run the tests / the walkthrough:
#   docker run --rm pqc-kv:phase1 python -m pytest tests -q
#   docker run --rm pqc-kv:phase1 python scripts/demo_lost_device.py
#
# Validate with the organizer toolkit (the toolkit is NOT in this repo; mount it
# read-only at run time):
#   docker run --rm -v /path/to/Track-4-Toolkit:/toolkit:ro \
#     -v "$PWD/track4_service.py:/toolkit/track4_service.py:ro" \
#     --tmpfs /tmp pqc-kv:phase1 python /toolkit/validate.py --entry /toolkit/track4_service.py

FROM python:3.12-slim-bookworm

# The judging runtime is an OFFLINE, read-only container. Those two properties are
# the reason for nearly everything below:
#   * no network at run time -> every dependency is baked in at build time;
#   * read-only root filesystem -> all state goes to /tmp (TRACK4_STATE_DIR or the
#     OS temp dir), never next to the code;
#   * one short-lived process per request -> no daemons, no supervisors, no caches
#     that assume a warm process.

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Refuse to install anything that would need a compiler. Every pin has a prebuilt
# wheel for cp312 on linux/amd64 (verified: see docs/PLATFORM_SUPPORT.md). If a
# future edit breaks that, the build fails here rather than silently growing a
# toolchain and a build-time network dependency.
ENV PIP_ONLY_BINARY=:all:

WORKDIR /app

# Dependencies first, in their own layer, so code edits do not re-resolve them.
COPY requirements.lock requirements-dev.lock ./
RUN python -m pip install --no-deps -r requirements.lock
# Test tooling is a separate locked file, installed only because this image is
# also the thing we run the suite in. The adapter itself needs neither pytest.
RUN python -m pip install --no-deps -r requirements-dev.lock

# Application code. No state, no keys, no .env, no toolkit content in the image.
COPY track4_service.py team_app.py threat-model.json ./
COPY src ./src
COPY tests ./tests
COPY scripts ./scripts
COPY docs ./docs

# Run unprivileged. The judging container's filesystem is read-only and state
# belongs in /tmp, so nothing else needs to be writable.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin app \
    && chown -R app:app /app
USER 10001

# We deliberately do NOT set TRACK4_STATE_DIR in the image. The contract says the
# local checker sets it, while the judging container leaves it unset and we fall
# back to the OS temp directory. Leaving it unset here means the default command
# exercises exactly the code path the judge will use. /tmp is the only writable
# place, and the adapter creates its private state dir under it (0700).

# CMD, not ENTRYPOINT, so `docker run <image> python -m pytest tests -q` works
# (a command after the image name replaces CMD).
CMD ["python", "-B", "/app/track4_service.py"]
