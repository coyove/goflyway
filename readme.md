# goflyway, HTTP tunnel in Go

goflyway is a tunnel proxy helping you fly across the wall. It is based entirely on HTTP protocol without any other 3rd party libraries. 

## Install

`go get` will show error " local import in non-local package", instead you should clone into directory outsite your `$GOPATH` directory:

```
$ git clone https://github.com/coyove/goflyway
$ cd goflyway
$ go install
```

## Run
If you want to try it now, simply run:
```
go run main.go -debug
```
on your local computer, or if you prefer your VPS, run:
```
go run main.go -k=KEY
```
at remote then run:
```
go run main.go -k=KEY -up=VPS_IP:8100
```
at local to connect.

Set your internet proxy to `127.0.0.1:8100` and enjoy.

## Console
There is a simple web console built inside goflyway: `http://127.0.0.1:8100/?goflyway-console`.

![](https://github.com/coyove/goflyway/blob/master/.misc/console.png?raw=true)

# Building instructions:
Building can now be done with:
```shell
make clean build
```

Or if you want to do it through Docker (if you don't have/want go installed on your local):
```shell
make -f docker.Makefile clean build
```

# Usage as a docker image:
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

## Others
When comes to speed, goflyway is nearly identical to shadowsocks. But HTTP has (quite large) overheads and goflyway will hardly be faster than those solutions running on their own protocols. (If your ISP deploys QoS, maybe goflyway gets some kinda faster.)

![](https://github.com/coyove/goflyway/blob/master/.misc/speed.png?raw=true)

However HTTP is much much easier to write and debug, I think this trade-off is absolutely acceptable. If you need more speed, try KCPTUN, BBR, ServerSpeeder...

## Android

I don't know much about programming on Android, but there is still way to run goflyway:

1. Install [Termux](https://f-droid.org/packages/com.termux/) and launch it
2. `pkg install golang`
3. `go run main.go -k=KEY -up=VPS_IP:8100`
4. Connect to wifi and set proxy to `127.0.0.1:8100`
5. Works on my XZP Android 7.0

![](https://github.com/coyove/goflyway/blob/master/.misc/android.jpg?raw=true)
