# goflyway - an encrypted HTTP server

![](https://raw.githubusercontent.com/coyove/goflyway/gdev/.misc/logo.png)

`master` is the active develop branch and containing v2 code, for the stable v1 release (though it was once called v2.0), please refer to [v1.0 branch](https://github.com/coyove/goflyway/tree/v1.0).

goflyway v2 is a special tool to forward local ports to a remote server securly, just like `ssh -L`.

goflyway uses pure HTTP POST requests to relay TCP connections. There is no CONNECT involved nor needed because goflyway is designed mainly for those people who are behind a CONNECT-less HTTP proxy or want to accelerate connections through basic CDNs.

However pure HTTP requesting is definitely a waste of bandwidth if you already have a better network environment, so use `-w` to turn on WebSocket relay, or `-K` to turn on KCP relay if possible.

## Usage
```
Forward localhost:1080 to server:1080

    ./goflyway -L 1080::1080 server:port -p password

Forward localhost:1080 to server2:1080 through server:port

    ./goflyway -L 1080:server2:1080 server:port -p password
```
