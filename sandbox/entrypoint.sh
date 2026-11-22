#!/bin/sh
# Starts the virtual desktop, the live-view server and the tool runner.
set -e

# Trust the egress proxy's CA so non-browser tools (python, curl, git, pip, node) can verify HTTPS through it. Only the PUBLIC
# certificate is mounted here (/airlock-ca, read-only); the CA's private key lives with the proxy and is never in this container.
# Without the certificate we stop, loudly, instead of running with a half-working sandbox.
CA=/airlock-ca/airlock-proxy-ca.crt
if [ ! -s "$CA" ]; then
  echo "FATAL: proxy CA certificate missing at $CA (run: make sandbox-up)" >&2
  exit 1
fi
cp "$CA" /usr/local/share/ca-certificates/airlock-proxy-ca.crt
update-ca-certificates > /dev/null

Xvfb :99 -screen 0 1280x800x24 &
sleep 1
fluxbox &
# No VNC password: reachable only through the localhost-bound viewer relay in docker-compose.yml.
x11vnc -display :99 -forever -shared -nopw -rfbport 5900 -quiet &
websockify --web=/usr/share/novnc 6080 localhost:5900 &
# Foreground: if the tool runner dies the container exits, so the failure is visible.
exec python3 /opt/tools/tool_runner.py serve
