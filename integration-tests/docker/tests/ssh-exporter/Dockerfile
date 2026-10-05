FROM alpine:3.23
RUN apk add --no-cache openssh curl \
    && adduser -D collector \
    && passwd -u collector \
    && mkdir -p /home/collector/.ssh /run/sshd \
    && chmod 700 /home/collector/.ssh
