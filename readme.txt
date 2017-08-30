goflyway, HTTP tunnel in Go

goflyway is a very simple tunnel proxy helping you fly across the wall. It is based entirely on HTTP protocol where overheads are inevitable, but I am trying to make its speed comparable with other solutions.

However goflyway is still under development and may crash due to long IO waits or other errors, if you want to try it now, simply run:
        go run main.go -debug
on your local computer, or if you prefer your VPS, run:
        go run main.go -k=<key>
then at local launch:
        go run main.go -k=<key> -up=<vps ip>:8100

Set your internet proxy to 127.0.0.1:8100, proxy username is "username" and password is "password". If you're using some programs which do not support proxy authentication natively (like Android), using the flag -disable-pa to disable the auth. 