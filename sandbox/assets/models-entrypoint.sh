#!/usr/bin/env bash
# The model server's entrypoint (local-models spec §3.4). It starts llama-server in router mode on port 8080 and
# ygg-modelgate on the gate's port in front of it. When either exits, it stops the other and exits with the code of
# the one that exited, so the container exits. A TERM or INT stops both.
#
# The gate's port comes from the environment:
#   YGG_MODELGATE_PORT  the port the gate listens on: the model list's server port, from 1 to 65535, never 8080
#                       (llama-server's). Required; the start (scripts/ygg-models.sh) sets it with -e.
# The start mounts these read-only: /models (the weights), /etc/ygg-models/preset.ini (from ygg models preset) and
# /etc/ygg-models/allowed (the allowed model's name, written by Odin; the gate reads it on each request).
set -u

port="${YGG_MODELGATE_PORT:-}"
bad() {
  echo "ygg-models: YGG_MODELGATE_PORT must be a port from 1 to 65535 other than 8080, which is llama-server's (got '${port}')" >&2
  exit 64
}
case "$port" in '' | *[!0-9]* | 0*) bad ;; esac
if [ "${#port}" -gt 5 ] || [ "$port" -gt 65535 ] || [ "$port" -eq 8080 ]; then bad; fi

llama-server --models-preset /etc/ygg-models/preset.ini --models-max 1 --host 0.0.0.0 --port 8080 &
server=$!
ygg-modelgate -listen ":${port}" -upstream http://127.0.0.1:8080 -allow /etc/ygg-models/allowed &
gate=$!
trap 'kill -TERM "$server" "$gate" 2>/dev/null' TERM INT

wait -n "$server" "$gate"
code=$?
kill -TERM "$server" "$gate" 2>/dev/null
wait "$server" "$gate" 2>/dev/null
exit "$code"
