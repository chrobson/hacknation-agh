# Minimal multi-purpose target image for the lab: OpenSSH server, socat (fake banners),
# busybox-extras (httpd, telnetd). One image, many small hosts.
FROM alpine:3.20.3
RUN apk add --no-cache openssh-server socat busybox-extras \
 && ssh-keygen -A \
 && adduser -D -s /bin/sh lab \
 && echo 'lab:lab' | chpasswd \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
CMD ["/usr/sbin/sshd", "-D", "-e"]
