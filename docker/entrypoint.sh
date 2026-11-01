#!/bin/sh
# unseenet-watchman in a container (docs: "In Docker").
#
#   (no arguments)        unseenet-watchman run, with /data/watchman.toml
#   init, run, check, status, unreport ...   that command
#   --version, -h         as unseenet-watchman
#   sh, python3, unseenet ...   run that program instead
#
# The vault's passphrase: a Docker secret (unseenet_vault_passphrase),
# UNSEENET_VAULT_PASSPHRASE_FILE, or UNSEENET_VAULT_PASSPHRASE. The core starts its
# own Tor; beside a node in compose, set nodes = ["node:1119"] in watchman.toml.
set -eu
DATA=${UNSEENET_DATA:-/data}
CONFIG=${UNSEENET_WATCHMAN_CONFIG:-$DATA/watchman.toml}

if [ "$(id -u)" = 0 ]; then
    if [ "$(stat -c %u "$DATA")" != 10001 ]; then
        chown -R unseenet:unseenet "$DATA"
    fi
    chmod 700 "$DATA"
    # A secret file is mounted as it is on the host (often root's, mode 600), so the
    # watchman's user may not read it: hand a copy on in /tmp (a tmpfs), readable by it only.
    for s in UNSEENET_VAULT_PASSPHRASE:unseenet_vault_passphrase; do
        var=${s%%:*} name=${s#*:}
        eval "f=\${${var}_FILE:-}"
        for f in "$f" "/run/secrets/$name"; do
            if [ -n "$f" ] && [ -r "$f" ]; then
                (umask 077 && cat "$f" > "/tmp/$name")
                chown unseenet:unseenet "/tmp/$name"
                export "${var}_FILE=/tmp/$name"
                break
            fi
        done
    done
    exec su-exec unseenet "$0" "$@"
fi
export HOME="$DATA"

case "${1:-}" in
    sh|ash|python3|unseenet|unseenet-*) exec "$@" ;;
    --version|-h|--help) exec unseenet-watchman "$@" ;;
esac

if [ -z "${UNSEENET_VAULT_PASSPHRASE:-}" ]; then
    for f in "${UNSEENET_VAULT_PASSPHRASE_FILE:-}" /run/secrets/unseenet_vault_passphrase; do
        if [ -n "$f" ] && [ -r "$f" ]; then
            UNSEENET_VAULT_PASSPHRASE=$(cat "$f")
            export UNSEENET_VAULT_PASSPHRASE
            break
        fi
    done
fi

if [ ! -f "$CONFIG" ]; then
    cp /opt/unseenet-watchman/watchman.example.toml "$CONFIG"
    echo "unseenet-watchman: wrote an example $CONFIG - edit it, run init, then start again." >&2
    exit 64
fi
cd "$DATA"
exec unseenet-watchman -c "$CONFIG" "${@:-run}"
