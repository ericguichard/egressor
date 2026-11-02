# Stage 1 — build amneziawg-go (userspace WireGuard daemon with Amnezia extensions)
FROM golang:1.24-alpine AS go-builder
RUN apk add --no-cache git
WORKDIR /src
RUN git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go .
RUN CGO_ENABLED=0 go build -v -o /bin/amneziawg-go .

# Stage 2 — build awg CLI tool (needed to configure AmneziaWG-specific UAPI params)
# and microsocks (tiny SOCKS5 server for sing-box integration)
FROM alpine:3.20 AS c-builder
RUN apk add --no-cache git gcc musl-dev make linux-headers libmnl-dev
WORKDIR /src
RUN git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-tools .
WORKDIR /src/src
RUN make

# microsocks — minimal single-threaded SOCKS5 server
WORKDIR /microsocks
RUN git clone --depth 1 https://github.com/rofl0r/microsocks .
RUN make

# Stage 3 — minimal runtime image
FROM alpine:3.20
RUN apk add --no-cache bash iproute2 iptables ip6tables
COPY --from=go-builder /bin/amneziawg-go /usr/local/bin/amneziawg-go
# amneziawg-tools builds the binary as 'wg' (AmneziaWG-extended variant)
COPY --from=c-builder  /src/src/wg          /usr/local/bin/awg
COPY --from=c-builder  /microsocks/microsocks /usr/local/bin/microsocks
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
