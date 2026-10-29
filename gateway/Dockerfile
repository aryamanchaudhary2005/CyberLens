FROM caddy:2.11.7-alpine

RUN apk add --no-cache curl \
    && addgroup -S -g 10001 cyberlens \
    && adduser -S -D -H -u 10001 -G cyberlens cyberlens \
    && mkdir -p /data /config \
    && chown -R cyberlens:cyberlens /data /config

COPY --chown=10001:10001 Caddyfile /etc/caddy/Caddyfile

ENV XDG_DATA_HOME=/data \
    XDG_CONFIG_HOME=/config

USER 10001:10001
EXPOSE 8443
HEALTHCHECK --interval=10s --timeout=4s --start-period=10s --retries=5 \
    CMD curl --fail --silent --insecure --resolve localhost:8443:127.0.0.1 https://localhost:8443/healthz || exit 1

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
