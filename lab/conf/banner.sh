#!/bin/sh
# banner.sh PORT TEXT... : tiny fake TCP service that sends one banner line (CRLF) and then
# swallows client input for up to 10 s. Used for services that only need a recognisable banner.
port="$1"; shift
printf '%s\r\n' "$*" > /tmp/banner
exec socat TCP-LISTEN:"$port",fork,reuseaddr SYSTEM:'cat /tmp/banner; timeout 10 cat >/dev/null'
