module gocaddywaytest

go 1.12

require github.com/caddyserver/caddy v1.0.1

require (
	github.com/coyove/common v0.0.0-20190703105334-7208554bb3f0 // indirect
	github.com/coyove/goflyway v1.0.10 // indirect
	github.com/coyove/goflyway/cmd/gocaddyway v0.0.0
)

replace github.com/coyove/goflyway/cmd/gocaddyway => ../
