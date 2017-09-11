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
