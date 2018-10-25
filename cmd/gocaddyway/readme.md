## Use goflyway in Caddy [beta]

### Build

1. Follow the [official guide](https://github.com/mholt/caddy#build) to run a working caddy server from source
2. In `caddy/caddymain/run.go`, add `_ "github.com/coyove/goflyway/cmd/gocaddyway"`
2. In `caddyhttp/httpserver/plugin.go`, add `goflyway` to `directives` at about line 600. (Don't add to the bottom, it should be in front of `locale`, the order is important)
2. Build caddy

### Binary

You can download the pre-compiled linux 64bit binary at release page, it is based on caddy `d3e3fc5`.

### Run

1. Prepare a Caddyfile and start the server, e.g.:
    ```
        http://:8100 {
            goflyway password
            proxy / http://example.com
        }
    ```
2. At local:
    ```
        ./goflyway -up xxx:8100 -k password
    ```
2. Done!

## Note

1. TCP multiplexer is not supported
2. Caddyfile hot reload is not supported, stop all and restart all
2. Normally you will config a host for your website, e.g.:
    ```
        http://example.com:80 {
            ...
            goflyway ...
        }
    ```
    In this case, you should specify the exact host at local in order to connect:
    ```
        ./goflyway -up gfw://example.com:80/example.com:80 -k ...
    ```
    Basically speaking, if you don't do this, goflyway will just connect `example.com` at port 80 and use a random host in the HTTP request. Caddy can't handle these cases and will only return 404. The second `example.com` in the above command forces goflyway to always use `example.com` as the host.
2. If you are using HTTPS, don't forget to use `-U https` at local:
    ```
        ./goflyway -up gfw://example.com:443/example.com:443 -U https -k ...
    ```