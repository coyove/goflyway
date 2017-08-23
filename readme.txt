goflyway, HTTP tunnel in Go

goflyway is a very simple tunnel proxy helping you fly across the wall. Its speed is nearly identical to SSR (sometimes a bit faster) while maintaining a low memory footprint.

However goflyway is still under development and may crash due to long IO waits or other errors, if you want to try it now, simply run:
        go run main.go -debug
on your local computer, or if you prefer your VPS, run:
        go run main.go -k=<key>
then at local launch:
        go run main.go -k=<key> -up=<vps ip>:8100

Set your internet proxy to 127.0.0.1:8100, proxy username is "username" and password is "password". If you're using some programs which do not support proxy authentication natively (like Android), using the flag -disable-pa to disable the auth. 

This program is not intended to keep you away from eavesdroppers because it doesn't use any strong cryptography algorithms (e.g. AES). It just simply implements a skip32 cipher to obfuscate the web traffic, making it harder for the firewall to identify, and FYI, skipjack algorithm is proved to be vulnerable, but just enough for one-time data exchange.

If you're accesing HTTPS through goflyway, good, if not, then we cannot guarantee the security of your data.