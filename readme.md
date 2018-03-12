# goflyway, HTTP tunnel in Go

![](https://raw.githubusercontent.com/coyove/goflyway/gdev/.misc/logo.png)

goflyway is an end-to-end encrypted HTTP/SOCKS5 proxy client/server written in golang, featuring:

1. TCP tunneling (opt. WebSocket relay)
2. TCP multiplexer
3. Man-in-the-middle proxy
4. UDP over TCP
5. Shadowsocks ACL rules compatibility
6. Server-side HTTP reverse proxy

For more info, please refer to the following links.

[中文](https://github.com/coyove/goflyway/wiki/%E4%BD%BF%E7%94%A8%E6%95%99%E7%A8%8B) / [English](https://github.com/coyove/goflyway/wiki/Getting-Started)

## Android Client

[shadowsocks-android](https://github.com/shadowsocks/shadowsocks-android/) is an Android client for shadowsocks. By replacing the native libss-local.so in /lib with goflyway's executable, we borrow its frontend to run our proxy on Android. Check this [wiki](https://github.com/coyove/goflyway/wiki/Android-%E5%AE%A2%E6%88%B7%E7%AB%AF) for details.

## Flags

### Developer Flags

| Flag | Default | Value(s) |
|------|---------|----------|
| -gen-ca | false | Generate certificate (ca.pem) and private key (key.pem) |
| -debug | false | Turn on debug mode |

### General Flags

| Flag | Default | Value(s) |
|------|---------|----------|
| -c | "" | Configuration file path |
| -lv, -log | Logging level ("dbg", "log", "warn", "err", "off") |
| -lf | "" | Log file |
| -a | "" | Proxy authentication (username:password) |
| -k | "0123456789abcdef" | Password |
| -l | -:8100" | Local listening address |
| -t | 20 | Close connections when they go idle for at least n seconds |

### Server Flags

| Flag | Default | Value(s) |
|------|---------|----------|
| -throt | 0 | Traffic throttling in bytes |
| -throt-max | 1024&#42;1024 | Traffic throttling token bucket max capacity |
| -disable-udp | false | -[S] disable UDP relay |
| -proxy-pass | -" | -[S] use goflyway as a reverse HTTP proxy |

### Client Flags

| Flag | Default | Value(s) |
|------|---------|----------|
| -g | false | Global proxy |
| -up | "" | Upstream server address (gfw, http, ws, cf, fwd, fwdws) |
| -partial | false | Partially encrypt the tunnel traffic |
| -udp-tcp | 1 | Use n TCP connections to relay UDP |
| -web-port | 8101 | Web console listening port, or 0 to disable |
| -dns-cache | 1024 | DNS cache size |
| -mux | 0 | Limit the total number of TCP connections, 0 means no limit |
| -vpn | false | VPN mode, used on Android only |
| -acl | "chinalist.txt" | ACL file |

### Shadowsocks-Compatible Flags

| Flag | Default | Value(s) |
|------|---------|----------|
| -p | "" | Server listening address |
| -u | true | Placeholder |
| -m | "" | Placeholder |
| -b | "" | Placeholder |
| -V | true | Placeholder |
| -fast-open | true | Placeholder |
