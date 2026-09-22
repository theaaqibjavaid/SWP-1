#!/bin/sh
# Retry a command with a bounded backoff. Shell has no AST adapter in SWP-1 and
# the lexical fallback covers no extension, so this file is a second example of
# what the walk refuses. See ../README.md.

ATTEMPTS=5
BASE_DELAY=2
MAX_DELAY=30

attempt() {
    target="$1"
    shift
    tries=0
    while [ "$tries" -lt "$ATTEMPTS" ]; do
        if "$@"; then
            return 0
        fi
        tries=$((tries + 1))
        delay=$((BASE_DELAY * tries))
        if [ "$delay" -gt "$MAX_DELAY" ]; then
            delay=$MAX_DELAY
        fi
        echo "attempt $tries for $target failed; waiting $delay" >&2
        sleep "$delay"
    done
    echo "gave up on $target after $tries attempts" >&2
    return 1
}
