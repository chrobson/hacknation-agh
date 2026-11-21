#!/bin/sh
# Fake "IoT router" telnet service (10.20.24.30:23): sends the BusyBox telnetd option negotiation and
# a login prompt as ONE write, then swallows client input for up to 10 s.
# Why not the real busybox telnetd: it sends the IAC bytes and the "\r\r\n<host> login: " prompt in
# separate writes that race each other, so `nmap -sV` reported version "" in some scans and
# "1.14.0 or later" in others (soft match on a partial read). That flake shows up as a false
# "changed" between runs. With one write nmap always reports product "BusyBox telnetd", version "".
port="${1:-23}"
printf '\377\375\001\377\375\037\377\373\001\377\373\003\r\r\nrouter login: ' > /tmp/telnet-banner
exec socat TCP-LISTEN:"$port",fork,reuseaddr SYSTEM:'cat /tmp/telnet-banner; timeout 10 cat >/dev/null'
