# Agent image for `isitsecure pentest --contained` (slice 3.0a — host protection).
#
# This image runs the WHOLE engagement inside a locked-down container so the
# operator's host (home dir, ~/.aws, ~/.ssh, files) is unreachable — the container
# is launched read-only, non-root, caps-dropped, with only a writable output dir
# mounted and the LLM API key injected via env (see isitsecure/engine/pentest/
# containment.py and docs/pentest.md "Contained mode").
#
# Build:  docker build -t isitsecure-pentest:latest .
# Run:    isitsecure pentest <url> --contained --i-am-authorized <host> ...
#
# Base pinned by tag (re-pin deliberately on a cadence).
FROM python:3.12-slim-bookworm

# Playwright browsers live at a fixed, world-readable path (NOT under $HOME, which is
# a tmpfs at runtime) so `crawl`/`xss_probe` work under a read-only rootfs + non-root user.
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

WORKDIR /app
COPY . /app

# Install the package with the extras a pentest needs (browser DAST, OOB, LLM, MCP),
# then the Playwright Chromium build + its OS deps (as root, into the shared path above).
RUN pip install ".[all]" \
    && python -m playwright install --with-deps chromium \
    && chmod -R a+rX "$PLAYWRIGHT_BROWSERS_PATH"

# Non-root user (uid/gid must match CONTAINER_UID_GID in containment.py). /out is the
# single writable mount for the engagement DB + report.
RUN groupadd --gid 10001 pentest \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/pentest pentest \
    && mkdir -p /out \
    && chown -R pentest:pentest /out /home/pentest

USER pentest
WORKDIR /home/pentest

# The CLI is the entrypoint; the contained runner appends `pentest <url> ...`.
ENTRYPOINT ["isitsecure"]
CMD ["--help"]
