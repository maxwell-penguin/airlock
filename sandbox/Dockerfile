# Sandbox image: virtual desktop + noVNC + Playwright Chromium + tool runner.
# Base pinned by digest (debian:bookworm-slim, arm64+amd64 index). Bump deliberately.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

ENV DEBIAN_FRONTEND=noninteractive \
    DISPLAY=:99 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright

RUN apt-get update && apt-get install -y --no-install-recommends \
      xvfb x11vnc fluxbox novnc websockify \
      python3 python3-pip python3-venv ca-certificates curl procps libatomic1 \
    && rm -rf /var/lib/apt/lists/*

# Playwright drives a real, headed Chromium on the virtual display so the live view shows it.
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir playwright==1.65.2 \
    && /opt/venv/bin/playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
ENV PATH=/opt/venv/bin:$PATH

COPY tool_runner.py /opt/tools/tool_runner.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /workspace /shots

WORKDIR /workspace
EXPOSE 6080
ENTRYPOINT ["/entrypoint.sh"]
