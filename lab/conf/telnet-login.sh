#!/bin/sh
# Login front-end for the "IoT router" telnetd (10.20.24.30:23).
# busybox login prints its prompt in several small writes right after telnetd's IAC negotiation,
# so nmap -sV sometimes saw a partial prompt (soft match, version "1.14.0 or later") and sometimes
# the full one (no version). Here the prompt is sent as ONE write after a short pause, so nmap
# always gets the same bytes: product "BusyBox telnetd", empty version, hostname "router".
sleep 1
printf 'router login: '
read -r user || exit 0
case "$user" in ""|-*) echo "Login incorrect"; exit 1 ;; esac
exec /bin/login "$user"
