#!/bin/sh
set -e

dir="${INTERNET_DIR:-/srv/internet}"

if [ ! -f "$dir/server.conf" ]; then
    set -- --public
    if [ -n "$INTERNET_PUBLIC_HOST" ]; then
        set -- "$@" --public-host "$INTERNET_PUBLIC_HOST"
    fi
    if [ -n "$INTERNET_DOMAIN" ]; then
        set -- "$@" --domain "$INTERNET_DOMAIN"
    fi
    if [ "$INTERNET_HTTPS" = "true" ]; then
        set -- "$@" --https
    fi
    internet-server init --dir "$dir" "$@"
fi

exec internet-server run --dir "$dir"
