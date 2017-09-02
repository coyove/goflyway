goflyway, HTTP tunnel in Go

goflyway is a tunnel proxy helping you fly across the wall. It is based entirely on HTTP protocol without any other 3rd party libraries, if you want to try it now, simply run:
        go run main.go -debug
on your local computer, or if you prefer your VPS, run:
        go run main.go -k=<key>
then at local launch:
        go run main.go -k=<key> -up=<vps ip>:8100

Set your internet proxy to 127.0.0.1:8100, proxy username is "username" and password is "password". If you're using some programs which do not support proxy authentication natively (like Android), using the flag -disable-pa to disable the auth. 

When comes to speed, goflyway is nearly identical to shadowsocks. But HTTP has (quite large) overheads and goflyway will never be faster than those solutions running on their own protocols. However HTTP is much much easier to write and debug, I think this trade-off is absolutely acceptable.

If you need more speed, try KCPTUN, BBR, ServerSpeeder...