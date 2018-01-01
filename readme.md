# goflyway, HTTP tunnel in Go

goflyway is an end-to-end encrypted HTTP/SOCKS5 proxy client/server written in golang, featuring:

1. TCP tunneling
2. TCP tunneling over WebSocket
3. Multiplex connections
4. Man-in-the-middle
5. UDP over TCP (SOCKS5)

For more info, please refer to the following links.

[中文](https://github.com/coyove/goflyway/wiki/%E4%BD%BF%E7%94%A8%E6%95%99%E7%A8%8B) / [English](https://github.com/coyove/goflyway/wiki/Getting-Started)

## Android Client

I modified [an Android client of shadowsocks](https://github.com/shadowsocks/shadowsocks-android/) by replacing its native libss-local.so with goflyway's executable. It works basicly, along with numerous bugs and broken features. Check this [wiki](https://github.com/coyove/goflyway/wiki/Android-%E5%AE%A2%E6%88%B7%E7%AB%AF) for details.