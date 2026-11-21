# Lab scanner: alpine + nmap. Runs inside the lab network (10.20.0.0/18) with NET_RAW/NET_ADMIN
# so that -sn ICMP/TCP pings and -sS SYN scans work as root.
# nmap is installed from Alpine packages at build time (NPSL: not redistributed in a published image).
FROM alpine:3.20.3
RUN apk add --no-cache nmap nmap-scripts libcap tini
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["sleep", "infinity"]
