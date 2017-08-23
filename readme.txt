GoFlyWay
HTTP tunnel in Go

GoFlyWay is a very simple tunnel proxy helping you fly across the wall. Its speed is nearly identical to SSR (sometimes a bit faster) while maintaining a low memory footprint.

However GoFlyWay is still under development and may crash due to long IO wait or other errors, if you want to try it now, simply run:
        go run main.go -debug
on your local computer, or if you prefer your VPS, run:
        go run main.go -k=<key>
then at local:
        go run main.go -k=<key> -up=<vps ip>:8100

set your internet proxy to 127.0.0.1:8100, proxy username is "username" and password is "password". Enjoy.