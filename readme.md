# goflyway, HTTP tunnel in Go

<svg viewBox="0 0 19 19" style="height: 80px; width: 80px; background: #676677; fill: #fff;"><path d="M3 3h13v13h-13v-5h5v1h-4v1h3v1h-3v2h7v-5h1v4h1v-3h1v3h1v-4h1v-3h-5v-4h1v3h3v-3h-4v-1h-3v1h-4v3h3v-1h-2v-1h3v3h-5v-5"/></svg>

goflyway is an end-to-end encrypted HTTP/SOCKS5 proxy client/server written in golang, featuring:

1. TCP tunneling
2. TCP tunneling over WebSocket
3. Multiplex connections
4. Man-in-the-middle
5. UDP over TCP (SOCKS5)

For more info, please refer to the following links.

[中文](https://github.com/coyove/goflyway/wiki/%E4%BD%BF%E7%94%A8%E6%95%99%E7%A8%8B) / [English](https://github.com/coyove/goflyway/wiki/Getting-Started)

## Android Client

[shadowsocks-android](https://github.com/shadowsocks/shadowsocks-android/) is an Android client for shadowsocks. By replacing the native libss-local.so in /lib with goflyway's executable, we borrow its frontend to run our proxy on Android. Check this [wiki](https://github.com/coyove/goflyway/wiki/Android-%E5%AE%A2%E6%88%B7%E7%AB%AF) for details.