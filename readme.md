# goflyway, HTTP tunnel in Go

goflyway is a tunnel proxy helping you fly across the wall. It is based entirely on HTTP protocol without any other 3rd party libraries. 

## Build & Run
Download the binary from [releases](https://github.com/coyove/goflyway/releases), on your VPS, launch the server by:
```
./goflyway -k=KEY
```
where `KEY` is the password, then at local run the client to connect:
```
./goflyway -up=VPS_IP:8100 -k=KEY
```
Set your Internet proxy to 127.0.0.1:8100 (HTTP) or 127.0.0.1:8101 (SOCKS5) and enjoy.

### Build from source
goflyway is still not yet completed, please do not `go get && go install` (because of ugly local imports), instead git cloned it directly:
```shell
git clone https://github.com/coyove/goflyway
cd goflyway
make build && cd build && ./goflyway -k=KEY
```

On windows (normally running a client) without `make`, you can:
```
./debug.bat -up=VPS_IP:8100 -k=KEY
```

### Usage as a docker image

If you want to do it through Docker (if you don't have/want go installed on your local):
```shell
make -f docker.Makefile clean build
```

Docker image can be built with:
```shell
make build_image
```

It's a multi-stage build so the size is ~8.23mb
```
❯ docker images | grep goflyway
coyove/goflyway                      latest                       68bd9fe5612e        7 minutes ago       8.23MB
```

Can be used like:

```
❯ docker run --rm -p 8102:8102 -p 8100:8100 -p 8101:8101 coyove/goflyway -debug
     __//                   __ _
    /.__.\                 / _| |
    \ \/ /      __ _  ___ | |_| |_   ___      ____ _ _   _
 '__/    \     / _' |/ _ \|  _| | | | \ \ /\ / / _' | | | |
  \-      )   | (_| | (_) | | | | |_| |\ V  V / (_| | |_| |
   \_____/     \__, |\___/|_| |_|\__, | \_/\_/ \__,_|\__, |
 ____|_|____    __/ |             __/ |               __/ |
     " "  cf   |___/             |___/               |___/

[W 0912 22:44:16.696] [WARNING] you are using the default key, please change it by setting -k=KEY
[  0912 22:44:16.696] debug mode on, port 8100 for local redirection, upstream on 8101
[  0912 22:44:16.696] listening on :8102
[  0912 22:44:16.697] socks5 proxy at :8101
[  0912 22:44:16.697] http proxy at :8100, upstream is 127.0.0.1:8101
```

## Console
There is a simple web console for client built inside goflyway: `http://127.0.0.1:8100/?goflyway-console`.

## Others
When comes to speed, goflyway is nearly identical to shadowsocks. But HTTP has (quite large) overheads and goflyway will hardly be faster than those solutions running on their own protocols. (If your ISP deploys QoS, maybe goflyway gets some kinda faster.)

![](https://github.com/coyove/goflyway/blob/master/.misc/speed.png?raw=true)

However HTTP is much much easier to write and debug, I think this trade-off is absolutely acceptable. If you need more speed, try KCPTUN, BBR, ServerSpeeder...

### Android

Currently there is no client on Android, here is a workaround:

1. Install [Termux](https://f-droid.org/packages/com.termux/) and launch it
2. `pkg install golang`
3. `go run main.go -k=KEY -up=VPS_IP:8100`
4. Connect to your WIFI and set its proxy to `127.0.0.1:8100`

Works on my XZP Android 7.0

![](https://github.com/coyove/goflyway/blob/master/.misc/android.jpg?raw=true)
