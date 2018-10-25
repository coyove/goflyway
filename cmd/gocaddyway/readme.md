## Use goflyway in Caddy [beta]

1. Follow the [official guide](https://github.com/mholt/caddy#build) to run a working caddy server from source
2. In `caddy/caddymain/run.go`, add `_ "github.com/coyove/goflyway/cmd/gocaddyway"`
2. In `caddyhttp/httpserver/plugin.go`, add `goflyway` to `directives` at about line 600. (Don't add to the bottom, it should be in front of `locale`, the order is important)
2. Build caddy
2. Prepare a Caddyfile and start the server, e.g.:
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