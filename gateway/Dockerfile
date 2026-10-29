FROM golang:1.27.3-alpine3.23 AS caddy-builder

RUN apk add --no-cache git \
    && go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.7

RUN mkdir -p /out \
    && xcaddy build v2.11.7 \
        --output /out/caddy \
        --replace github.com/go-jose/go-jose/v4=github.com/go-jose/go-jose/v4@v4.1.6 \
        --replace golang.org/x/net=golang.org/x/net@v0.60.0

FROM caddy:2.11.7-alpine

USER root

RUN apk add --no-cache curl \
    && apk upgrade --no-cache \
    && addgroup -S -g 10001 cyberlens \
    && adduser -S -D -H -u 10001 -G cyberlens cyberlens \
    && mkdir -p /data /config \
    && chown -R cyberlens:cyberlens /data /config

COPY --from=caddy-builder /out/caddy /usr/bin/caddy
COPY --chown=10001:10001 Caddyfile /etc/caddy/Caddyfile

ENV XDG_DATA_HOME=/data \
    XDG_CONFIG_HOME=/config

USER 10001:10001
EXPOSE 8443
HEALTHCHECK --interval=10s --timeout=4s --start-period=10s --retries=5 \
    CMD curl --fail --silent --insecure --resolve localhost:8443:127.0.0.1 https://localhost:8443/healthz || exit 1

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
