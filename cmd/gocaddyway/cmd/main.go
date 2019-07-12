package main

import (
	"github.com/caddyserver/caddy/caddy/caddymain"
	// plug in plugins here, for example:
	_ "github.com/coyove/goflyway/cmd/gocaddyway"
)

func main() {
	// optional: disable telemetry
	// caddymain.EnableTelemetry = false
	caddymain.Run()
}
