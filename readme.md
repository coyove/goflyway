# goflyway, HTTP tunnel in Go

goflyway is a tunnel proxy based entirely on HTTP protocol without any other 3rd party libraries.

[中文](https://github.com/coyove/goflyway/wiki/%E4%BD%BF%E7%94%A8%E6%95%99%E7%A8%8B)

## Build & Run
Download the binary from [releases](https://github.com/coyove/goflyway/releases), on your sevrer, launch goflyway:
```
./goflyway -k=KEY
```
where `KEY` is the password, then at your local run the client to connect:
```
./goflyway -up=SERVER_IP:8100 -k=KEY
```
Set your Internet proxy to 127.0.0.1:8100 (HTTP or SOCKS5 protocol) and enjoy.

### Build from source
Get the lastest release of golang and setup a correct `GOPATH`, then:
```shell
go get -u github.com/coyove/goflyway/cmd/goflyway
cd $GOPATH/bin
./goflyway -k=KEY
```

### Use a docker image
If you want to do it through Docker, run:
```shell
make -f docker.Makefile clean build
```

Docker image can be built with:
```shell
make build_image
```

## Key
`KEY` in goflyway is merely a password, but if you are not using the same one (intentional or mistyping) server uses, you get banned. 

Once on the blacklist, all requests you sent will be discarded and there is no auto discharge, you have to either manually restart the server and try again (check your key first), or click "Unlock Me" in the goflyway console (again, please check your key).

## Console
There is a simple web console for client built inside goflyway: `http://127.0.0.1:8100/?goflyway-console`.

## UDP
We have an experimental SOCKS5 UDP relay, turn it on (both at client and server):
```
./goflyway YOUR_OTHER_COMMANDS -u 8731
```
note that the listening port (`8731` in this example) should be identical at both sides. 

goflyway (only) uses TCP to relay UDP, which is bound to be slow. Use the flag `-udp-tcp N` and increase N progressively (default 1) to tweak the performance.

UDP relay is only tested under a limited number of programs (Skype, Discord, etc.) using [SocksCap64](https://sourceforge.net/projects/sockscap64/), problem reports are welcome. (BTW, dnscrypt is not working)

## Reverse proxy
The goflyway server is actually an HTTP server with special proxy functions, so you can indeed use it as a normal HTTP server without problems. Just pass `-proxy-pass http://xxx.xxx.xxx.xxx:xx` to the server and it will act as a reverse proxy.
```
     +---------+                          +-----------------+
     | browser |-.                      .-| your web server |
     +---------+  \    +----------+    /  +-----------------+
                   }==>| goflyway |==={   
+--------------+  /    +----------+    \  +----------------+
| proxy client |-'                      '-| GFWed websites |
+--------------+                          +----------------+
```

## Man-in-the-Middle
Import `ca.pem` into your system's trusted root certificates store and use `-mitm` to enable main-in-the-middle proxy mode (note it can only be activated when using HTTP proxy). 

Under MITM all HTTPS data will be sent in plain HTTP with body and some important headers encrypted (like `Cookie`), also XMPP and Websocket won't work in MITM.

Since `ca.pem` is public accessible in this repo, trusting it would be quite risky, it is recommended to use `./goflyway -gen-ca` to generate a new ca (then import).

## Speed
When comes to speed, goflyway is nearly identical to shadowsocks. But HTTP has (quite large) overheads and goflyway will hardly be faster than those solutions running on their own protocols. (If your ISP deploys QoS, maybe goflyway gets some kinda faster.)

However HTTP is much much easier to write and debug, I think this trade-off is absolutely acceptable. If you need more speed, try KCPTUN, BBR, ServerSpeeder...

## Android

Currently there is no client on Android, here is a workaround:

1. Install [Termux](https://f-droid.org/packages/com.termux/) and launch it
2. `pkg install golang`
3. `go run main.go -k=KEY -up=SERVER_IP:8100`
4. Connect to your WIFI and set its proxy to `127.0.0.1:8100`

Works on my XZP Android 7.0

![](https://github.com/coyove/goflyway/blob/master/.misc/android.jpg?raw=true)
