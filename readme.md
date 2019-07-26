# goflyway v2 - an HTTP-based local port forwarder

![](https://raw.githubusercontent.com/coyove/goflyway/gdev/.misc/logo.png)

`master` is the active develop branch and containing v2 code, for the stable v1 release (though it was once called v2.0), please refer to [v1.0 branch](https://github.com/coyove/goflyway/tree/v1.0).

goflyway v2 is a special tool to forward local ports to a remote server securly, just like `ssh -L`.

goflyway uses pure HTTP POST requests to relay TCP connections. There is no CONNECT involved nor needed because goflyway is designed mainly for those people who are behind a CONNECT-less HTTP proxy or want to accelerate connections through basic CDNs.

However pure HTTP requesting is definitely a waste of bandwidth if you already have a better network environment, so use `-w` to turn on WebSocket relay, or `-K` to turn on KCP relay if possible.

## Usage
```
Forward localhost:1080 to server:1080

    Server: ./goflyway :port
    Client: ./goflyway -L 1080::1080 server:port -p password

Forward localhost:1080 to server2:1080 through server:port using WebSocket

    Server: ./goflyway :port
    Client: ./goflyway -w -L 1080:server2:1080 server:port -p password

Server as well as an HTTP reversed proxy or static file server on the same port:

    Server: ./goflyway :port -I http://127.0.0.1:8080
    Server: ./goflyway :port -I /var/www/html
```

## Write Buffer

In HTTP mode when server received some data it can't just send them to the client directly because HTTP is not bi-directional, instead the server must wait until the client requests them, which means these data will be stored in memory for some time.

You can use `-W bytes` to limit the maximum bytes a server can buffer (for each connection), by default it is 1048576 (1M). If the buffer reaches the limit, the following bytes will be blocked until the buffer has free space for them.
