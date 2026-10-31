FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tor ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY torrc /etc/tor/torrc
USER debian-tor
EXPOSE 9050
CMD ["tor", "-f", "/etc/tor/torrc"]
