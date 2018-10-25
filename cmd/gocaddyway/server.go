package gocaddyway

import (
	"net/http"

	"github.com/coyove/common/logg"
	"github.com/coyove/goflyway/proxy"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

type gofwHandler struct {
	Next httpserver.Handler
	gofw *proxy.ProxyServer
}

func init() {
	caddy.RegisterPlugin("goflyway", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {

	c.Next()
	if !c.NextArg() {
		return c.ArgErr()
	}

	cipher := proxy.NewCipher(c.Val(), proxy.FullCipher)
	cipher.IO.Logger = logg.NewLogger("off")
	cipher.IO.Start(20)
	sc := &proxy.ServerConfig{
		Cipher:       cipher,
		LBindTimeout: 10,
		LBindCap:     256,
		Logger:       cipher.IO.Logger,
	}

	cfg := httpserver.GetConfig(c)
	mid := func(next httpserver.Handler) httpserver.Handler {
		server, _ := proxy.NewServer("0.0.0.0:0", sc)
		return gofwHandler{
			Next: next,
			gofw: server,
		}
	}
	cfg.AddMiddleware(mid)

	c.OnShutdown(func() error {
		cipher.IO.Stop()
		return nil
	})
	return nil
}

func (h gofwHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if h.gofw.ServeHTTPImpl(w, r) {
		return 0, nil
	}
	return h.Next.ServeHTTP(w, r)
}
